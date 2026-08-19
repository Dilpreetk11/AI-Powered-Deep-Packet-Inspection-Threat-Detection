// Multi-threaded DPI Engine - AI-Enhanced Version
// Architecture: Reader -> LB threads -> FP threads (with AIEngine) -> Output

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "ai_engine.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;

    // AI-specific state
    std::vector<float> pkt_lengths;
    std::vector<float> pkt_iats;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    double total_payload_entropy = 0.0;
    uint32_t payload_entropy_count = 0;
    uint32_t syn_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    uint64_t bytes_in = 0;    // src->dst
    uint64_t bytes_out = 0;   // dst->src (approximated as total - bytes_in)
    bool ai_evaluated = false;
    uint32_t ai_threat_score = 0;
    std::string ai_threat_level = "LOW";
    std::string ai_rationale;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};

    // AI stats
    std::atomic<uint64_t> ai_evaluations{0};
    std::atomic<uint64_t> ai_high_threat{0};
    std::atomic<uint64_t> ai_medium_threat{0};
    std::atomic<uint64_t> ai_blocked_by_ai{0};
    
    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;

    // High-threat flow details
    struct ThreatRecord {
        std::string flow_id;
        uint32_t threat_score;
        std::string threat_level;
        std::string rationale;
    };
    std::vector<ThreatRecord> threat_records;
    
    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }

    void recordThreat(const std::string& flow_id, uint32_t score, const std::string& level, const std::string& rationale) {
        std::lock_guard<std::mutex> lock(app_mutex);
        if (threat_records.size() < 20) {  // cap stored records
            threat_records.push_back({flow_id, score, level, rationale});
        }
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue,
             AIEngine* ai_engine = nullptr, uint32_t ai_threshold = 70)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue),
          ai_engine_(ai_engine), ai_threat_threshold_(ai_threshold) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    AIEngine* ai_engine_;
    uint32_t ai_threat_threshold_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    // Build a Connection-like object from FlowEntry so AIEngine can evaluate it
    Connection buildConnectionProxy(const FlowEntry& flow) const {
        Connection conn;
        conn.tuple = flow.tuple;
        conn.sni = flow.sni;
        conn.app_type = flow.app_type;
        conn.packets_in = flow.packets;
        conn.packets_out = 0;
        conn.bytes_in = flow.bytes_in;
        conn.bytes_out = flow.bytes_out;
        conn.first_seen = flow.first_seen;
        conn.last_seen = flow.last_seen;
        conn.pkt_lengths = flow.pkt_lengths;
        conn.pkt_iats = flow.pkt_iats;
        conn.total_payload_entropy = flow.total_payload_entropy;
        conn.payload_entropy_count = flow.payload_entropy_count;
        conn.syn_count = flow.syn_count;
        conn.fin_count = flow.fin_count;
        conn.rst_count = flow.rst_count;
        return conn;
    }

    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            auto now = std::chrono::steady_clock::now();
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
                flow.first_seen = now;
            }
            flow.last_seen = now;
            flow.packets++;
            flow.bytes += pkt.data.size();
            flow.bytes_in += pkt.data.size();  // simplified: all bytes counted as inbound

            // ── Sequence feature update for AI ────────────────────────────
            if (flow.pkt_lengths.size() < 8) {
                flow.pkt_lengths.push_back(static_cast<float>(pkt.data.size()));
                if (flow.pkt_lengths.size() >= 2) {
                    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
                        now - flow.first_seen).count();
                    float iat = static_cast<float>(dur) / 1e6f / static_cast<float>(flow.pkt_lengths.size() - 1);
                    flow.pkt_iats.push_back(iat);
                }
            }
            // TCP flag counts
            if (pkt.tcp_flags & 0x02) flow.syn_count++;
            if (pkt.tcp_flags & 0x01) flow.fin_count++;
            if (pkt.tcp_flags & 0x04) flow.rst_count++;

            // Payload entropy
            if (pkt.payload_length > 0 && ai_engine_) {
                const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
                double entropy = ai_engine_->calculatePayloadEntropy(payload, pkt.payload_length);
                flow.total_payload_entropy += entropy;
                flow.payload_entropy_count++;
            }
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            // Check rule-based blocking
            if (!flow.blocked) {
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
            }

            // ── AI evaluation (lazy, after min_packets gathered) ──────────
            if (ai_engine_ && !flow.ai_evaluated && flow.packets >= 5) {
                Connection proxy = buildConnectionProxy(flow);
                AIResult ai_res = ai_engine_->evaluateFlow(proxy);
                flow.ai_evaluated = true;
                flow.ai_threat_score = ai_res.threat_score;
                flow.ai_threat_level = ai_res.threat_level;
                flow.ai_rationale = ai_res.rationale;

                stats_->ai_evaluations++;
                if (ai_res.threat_score >= 70) {
                    stats_->ai_high_threat++;
                    // Derive a flow ID string from the 5-tuple
                    auto& t = pkt.tuple;
                    auto ip_str = [](uint32_t ip) {
                        return std::to_string(ip & 0xFF) + "." +
                               std::to_string((ip >> 8) & 0xFF) + "." +
                               std::to_string((ip >> 16) & 0xFF) + "." +
                               std::to_string((ip >> 24) & 0xFF);
                    };
                    std::string flow_id = ip_str(t.src_ip) + ":" + std::to_string(t.src_port) +
                                         " -> " + ip_str(t.dst_ip) + ":" + std::to_string(t.dst_port);
                    stats_->recordThreat(flow_id, ai_res.threat_score, ai_res.threat_level, ai_res.rationale);

                    // Block if score exceeds threshold
                    if (ai_res.threat_score >= ai_threat_threshold_) {
                        flow.blocked = true;
                        stats_->ai_blocked_by_ai++;
                    }
                } else if (ai_res.threat_score >= 40) {
                    stats_->ai_medium_threat++;
                }
            }
            
            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            
            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        
        // DNS
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }
        
        // Port-based fallback (but don't mark as classified - might get SNI later)
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
        bool ai_enabled = true;
        uint32_t ai_threshold = 70;  // 0-100 threat score to block
    };
    
    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║        DPI ENGINE v2.0 (Multi-threaded + AI-Enhanced)         ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "║ AI Engine: " << (cfg.ai_enabled ? "ENABLED" : "DISABLED")
                  << "    Threat Threshold: " << std::setw(3) << cfg.ai_threshold << "              ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Initialize AI engine
        if (cfg.ai_enabled) {
            AIConfig ai_cfg;
            ai_cfg.enabled = true;
            ai_cfg.threat_threshold = cfg.ai_threshold;
            ai_cfg.min_packets_for_inference = 5;
            ai_cfg.verbose = false;
            ai_engine_ = std::make_unique<AIEngine>(ai_cfg);
            ai_engine_->initialize();
            std::cout << "[AI Engine] Initialized. Threat threshold = " << cfg.ai_threshold << "\n\n";
        }
        
        // Create FP threads (pass AI engine pointer)
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(
                i, &rules_, &stats_, &output_queue_,
                ai_engine_.get(), cfg.ai_threshold
            ));
        }
        
        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    
    bool process(const std::string& input_file, const std::string& output_file) {
        // Open input
        PcapReader reader;
        if (!reader.open(input_file)) return false;
        
        // Open output
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Cannot open output file\n";
            return false;
        }
        
        // Write PCAP header
        const auto& hdr = reader.getGlobalHeader();
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        
        // Start all threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
        
        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;
                
                PcapPacketHeader phdr;
                phdr.ts_sec = pkt_opt->ts_sec;
                phdr.ts_usec = pkt_opt->ts_usec;
                phdr.incl_len = pkt_opt->data.size();
                phdr.orig_len = pkt_opt->data.size();
                
                output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
            }
        });
        
        // Read and dispatch packets
        std::cout << "[Reader] Processing packets...\n";
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;
        
        while (reader.readNextPacket(raw)) {
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
            
            // Create packet
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);
            
            // Parse 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            
            // Calculate payload offset
            pkt.payload_offset = 14;  // Ethernet
            if (pkt.data.size() > 14) {
                uint8_t ip_ihl = pkt.data[14] & 0x0F;
                pkt.payload_offset += ip_ihl * 4;
                
                if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                    uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                    pkt.payload_offset += tcp_off * 4;
                } else if (parsed.has_udp) {
                    pkt.payload_offset += 8;
                }
                
                if (pkt.payload_offset < pkt.data.size()) {
                    pkt.payload_length = pkt.data.size() - pkt.payload_offset;
                } else {
                    pkt.payload_length = 0;
                }
            }
            
            // Update stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;
            
            // Dispatch to LB (hash-based)
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }
        
        std::cout << "[Reader] Done reading " << pkt_id << " packets\n";
        reader.close();
        
        // Wait for queues to drain
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Stop all threads
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        output_running = false;
        output_queue_.shutdown();
        output_thread.join();
        
        output.close();
        
        // Print report
        printReport();
        
        return true;
    }

private:
    Config config_;
    Rules rules_;
    Stats stats_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    std::unique_ptr<AIEngine> ai_engine_;
    
    void printReport() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           ║\n";
        std::cout << "║ Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           ║\n";
        std::cout << "║ TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           ║\n";
        
        // Thread stats
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ THREAD STATISTICS                                             ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           ║\n";
        }
        
        // App distribution
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');
            
            std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  ║\n";
        }
        
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        // Detected SNIs
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }

        // AI Threat Report
        if (config_.ai_enabled) {
            std::cout << "\n";
            std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                   AI THREAT INTELLIGENCE                      ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::cout << "║ Total AI Evaluations: " << std::setw(10) << stats_.ai_evaluations.load() << "                          ║\n";
            std::cout << "║ HIGH Threat Flows:    " << std::setw(10) << stats_.ai_high_threat.load()  << "                          ║\n";
            std::cout << "║ MEDIUM Threat Flows:  " << std::setw(10) << stats_.ai_medium_threat.load()<< "                          ║\n";
            std::cout << "║ Blocked by AI Score:  " << std::setw(10) << stats_.ai_blocked_by_ai.load()<< "                          ║\n";
            std::cout << "║ Threat Threshold:     " << std::setw(10) << config_.ai_threshold          << "                          ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            if (!stats_.threat_records.empty()) {
                std::cout << "║ TOP THREAT FLOWS:                                             ║\n";
                for (const auto& rec : stats_.threat_records) {
                    std::string line = "║  [" + rec.threat_level + "] Score:" +
                        std::to_string(rec.threat_score) + " " + rec.flow_id;
                    // Pad to 63 chars
                    if (line.size() < 63) line += std::string(63 - line.size(), ' ');
                    std::cout << line.substr(0, 63) << "║\n";
                    std::string reason = "║     -> " + rec.rationale;
                    if (reason.size() < 63) reason += std::string(63 - reason.size(), ' ');
                    std::cout << reason.substr(0, 63) << "║\n";
                }
            } else {
                std::cout << "║  No high-threat flows detected.                               ║\n";
            }
            std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        }
    }
};

// =============================================================================
// Main
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection (AI-Enhanced)
======================================================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --ai-threshold <n>     AI threat score block threshold 0-100 (default: 70)
  --no-ai                Disable AI engine entirely

Example:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --ai-threshold 60
)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input = argv[1];
    std::string output = argv[2];
    
    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--ai-threshold" && i + 1 < argc) cfg.ai_threshold = static_cast<uint32_t>(std::stoi(argv[++i]));
        else if (arg == "--no-ai") cfg.ai_enabled = false;
    }
    
    DPIEngine engine(cfg);
    
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    
    if (!engine.process(input, output)) {
        return 1;
    }
    
    std::cout << "\nOutput written to: " << output << "\n";
    return 0;
}
