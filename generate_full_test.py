#!/usr/bin/env python3
"""
Generate a FULL test PCAP with all threat levels:
  - BENIGN flows (LOW)
  - SYN Flood attack (HIGH/CRITICAL -> BLOCK)
  - Obfuscated Tunnel (HIGH -> BLOCK)
  - Data Exfiltration (HIGH -> BLOCK)
  - C2 Beaconing (HIGH -> BLOCK)
  - Normal HTTPS/HTTP/DNS flows (LOW -> ALLOW)
"""
import struct
import random
import os

class PCAPWriter:
    def __init__(self, filename):
        os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
        self.file = open(filename, 'wb')
        self.file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.timestamp = 1700000000
        self.usec = 0

    def write_packet(self, data):
        self.usec = (self.usec + random.randint(1000, 50000)) % 1000000
        if self.usec < 50000:
            self.timestamp += 1
        self.file.write(struct.pack('<IIII', self.timestamp, self.usec, len(data), len(data)))
        self.file.write(data)

    def close(self):
        self.file.close()

def eth(src='00:11:22:33:44:55', dst='aa:bb:cc:dd:ee:ff'):
    return bytes.fromhex(dst.replace(':','')) + bytes.fromhex(src.replace(':','')) + b'\x08\x00'

def ip_hdr(src_ip, dst_ip, proto, payload_len):
    total = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, total, random.randint(1,65535), 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src_ip.split('.'))
    hdr += bytes(int(x) for x in dst_ip.split('.'))
    return hdr

def tcp_hdr(sp, dp, flags, seq=None, ack=0):
    if seq is None: seq = random.randint(1000, 99999)
    return struct.pack('>HHIIBHH', sp, dp, seq, ack, 0x50, flags, 65535)

def udp_hdr(sp, dp, payload_len):
    return struct.pack('>HHHH', sp, dp, 8 + payload_len, 0)

def make_tcp(w, src_ip, dst_ip, sp, dp, flags, payload=b'', src_mac='00:11:22:33:44:55'):
    tcp = tcp_hdr(sp, dp, flags)
    ip  = ip_hdr(src_ip, dst_ip, 6, len(tcp) + len(payload))
    w.write_packet(eth(src_mac) + ip + tcp + payload)

def make_udp(w, src_ip, dst_ip, sp, dp, payload=b''):
    udp = udp_hdr(sp, dp, len(payload))
    ip  = ip_hdr(src_ip, dst_ip, 17, len(udp) + len(payload))
    w.write_packet(eth() + ip + udp + payload)

def tls_hello(sni):
    sni_b = sni.encode()
    sni_ext = struct.pack('>HH', 0x0000, len(sni_b)+5) + struct.pack('>HBH', len(sni_b)+3, 0, len(sni_b)) + sni_b
    exts = sni_ext
    body = b'\x03\x03' + bytes(random.randint(0,255) for _ in range(32))
    body += b'\x00\x00\x04\x13\x01\x13\x02\x01\x00'
    body += struct.pack('>H', len(exts)) + exts
    hs = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs

def random_high_entropy_payload(size):
    return bytes(random.randint(0, 255) for _ in range(size))

def main():
    w = PCAPWriter('test_full_threats.pcap')
    print("[+] Generating full threat test PCAP...")

    # =========================================================
    # 1. BENIGN TRAFFIC (LOW threat, ALLOW)
    # =========================================================
    print("  [1/5] Normal HTTPS/HTTP/DNS flows (LOW/ALLOW)...")
    benign_sites = [
        ('142.250.185.206', 'www.google.com'),
        ('142.250.185.110', 'www.youtube.com'),
        ('157.240.1.35',    'www.facebook.com'),
        ('140.82.114.4',    'github.com'),
        ('104.16.85.20',    'discord.com'),
        ('35.186.224.25',   'zoom.us'),
        ('99.86.0.100',     'www.tiktok.com'),
        ('17.253.144.10',   'www.apple.com'),
    ]
    user = '192.168.1.100'
    for dst_ip, sni in benign_sites:
        sp = random.randint(49152, 65535)
        # Full TCP handshake + TLS Hello (5+ pkts to trigger ML)
        make_tcp(w, user, dst_ip, sp, 443, 0x02)          # SYN
        make_tcp(w, dst_ip, user, 443, sp, 0x12)          # SYN-ACK
        make_tcp(w, user, dst_ip, sp, 443, 0x10)          # ACK
        make_tcp(w, user, dst_ip, sp, 443, 0x18, tls_hello(sni))   # TLS ClientHello
        make_tcp(w, dst_ip, user, 443, sp, 0x18, bytes(200))        # Server response
        make_tcp(w, user, dst_ip, sp, 443, 0x18, bytes(400))        # App data
        make_tcp(w, dst_ip, user, 443, sp, 0x18, bytes(1200))       # App data

    # HTTP flows
    for dst_ip, host in [('93.184.216.34','example.com'), ('185.199.108.153','httpbin.org')]:
        sp = random.randint(49152, 65535)
        http = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        make_tcp(w, user, dst_ip, sp, 80, 0x02)
        make_tcp(w, dst_ip, user, 80, sp, 0x12)
        make_tcp(w, user, dst_ip, sp, 80, 0x10)
        make_tcp(w, user, dst_ip, sp, 80, 0x18, http)
        make_tcp(w, dst_ip, user, 80, sp, 0x18, b'HTTP/1.1 200 OK\r\n\r\n' + bytes(500))
        make_tcp(w, user, dst_ip, sp, 80, 0x01)  # FIN

    # DNS
    for domain in ['www.google.com', 'www.youtube.com', 'api.discord.com']:
        parts = domain.split('.')
        dns = struct.pack('>HHHHHH', random.randint(1,65535), 0x0100, 1, 0, 0, 0)
        for p in parts:
            dns += bytes([len(p)]) + p.encode()
        dns += b'\x00\x00\x01\x00\x01'
        make_udp(w, user, '8.8.8.8', random.randint(1024,65535), 53, dns)

    # =========================================================
    # 2. SYN FLOOD ATTACK (HIGH/CRITICAL -> BLOCK)
    #    Model expects: pkts_src>20, pkts_dst=0, syn_count=pkts_src, tiny pkts
    # =========================================================
    print("  [2/5] SYN Flood attack (CRITICAL/BLOCK)...")
    attacker = '10.0.0.50'
    victim   = '192.168.1.1'
    # Send 60 SYN-only packets from same attacker->victim on different src ports
    # This creates ONE flow with 60 pkts_src, 0 pkts_dst, 60 syn_count
    sp_flood = 12345
    for i in range(60):
        # Vary source port slightly but keep 5-tuple the same (attacker->victim:80 TCP)
        make_tcp(w, attacker, victim, sp_flood, 80, 0x02,
                 b'\x00' * 4,  # tiny payload — 54-byte SYN packet
                 src_mac='de:ad:be:ef:00:01')

    # =========================================================
    # 3. OBFUSCATED TUNNEL (HIGH → BLOCK)
    #    Model expects: entropy ~7.9+, port 4444/5555/31337, no SNI
    # =========================================================
    print("  [3/5] Obfuscated Tunnel (HIGH/BLOCK)...")
    tunnel_src = '10.0.0.77'
    tunnel_dst = '203.0.113.1'
    sp_t = 54321
    dp_t = 4444
    make_tcp(w, tunnel_src, tunnel_dst, sp_t, dp_t, 0x02, src_mac='de:ad:be:ef:00:02')
    make_tcp(w, tunnel_dst, tunnel_src, dp_t, sp_t, 0x12)
    make_tcp(w, tunnel_src, tunnel_dst, sp_t, dp_t, 0x10, src_mac='de:ad:be:ef:00:02')
    # 30+ packets of near-maximum-entropy data — triggers high entropy signal
    for _ in range(30):
        payload = random_high_entropy_payload(random.randint(900, 1300))
        make_tcp(w, tunnel_src, tunnel_dst, sp_t, dp_t, 0x18, payload, src_mac='de:ad:be:ef:00:02')
    for _ in range(20):
        payload = random_high_entropy_payload(random.randint(700, 1000))
        make_tcp(w, tunnel_dst, tunnel_src, dp_t, sp_t, 0x18, payload)

    # =========================================================
    # 4. DATA EXFILTRATION (HIGH → BLOCK)
    #    Model: massive bytes_src, tiny bytes_dst, high entropy, port 8080
    # =========================================================
    print("  [4/5] Data Exfiltration (HIGH/BLOCK)...")
    exfil_src = '192.168.1.55'
    exfil_dst = '198.51.100.9'
    sp_e = 33333
    dp_e = 8080   # suspicious exfil port
    make_tcp(w, exfil_src, exfil_dst, sp_e, dp_e, 0x02, src_mac='de:ad:be:ef:00:03')
    make_tcp(w, exfil_dst, exfil_src, dp_e, sp_e, 0x12)
    make_tcp(w, exfil_src, exfil_dst, sp_e, dp_e, 0x10, src_mac='de:ad:be:ef:00:03')
    # 100+ max-size outbound data packets (huge upload), near-max entropy
    for _ in range(100):
        payload = random_high_entropy_payload(1400)  # MTU-sized — max entropy upload
        make_tcp(w, exfil_src, exfil_dst, sp_e, dp_e, 0x18, payload, src_mac='de:ad:be:ef:00:03')
    # Very tiny response (2 pkts back)
    make_tcp(w, exfil_dst, exfil_src, dp_e, sp_e, 0x18, bytes(80))
    make_tcp(w, exfil_dst, exfil_src, dp_e, sp_e, 0x18, bytes(60))
    make_tcp(w, exfil_src, exfil_dst, sp_e, dp_e, 0x01, src_mac='de:ad:be:ef:00:03')

    # =========================================================
    # 5. C2 BEACONING (HIGH → BLOCK)
    #    Model: symmetric pkts, rigid tiny fixed-size, fast regular IAT, port 443/8443
    # =========================================================
    print("  [5/5] C2 Beaconing (HIGH/BLOCK)...")
    c2_src = '192.168.1.88'
    c2_dst = '45.33.32.156'
    sp_c = 44444
    dp_c = 8443
    make_tcp(w, c2_src, c2_dst, sp_c, dp_c, 0x02, src_mac='de:ad:be:ef:00:04')
    make_tcp(w, c2_dst, c2_src, dp_c, sp_c, 0x12)
    make_tcp(w, c2_src, c2_dst, sp_c, dp_c, 0x10, src_mac='de:ad:be:ef:00:04')
    # Fixed 112-byte beacon every iteration — very rigid pattern
    beacon = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 28)   # 112 bytes, rigid
    for _ in range(50):
        make_tcp(w, c2_src, c2_dst, sp_c, dp_c, 0x18, beacon, src_mac='de:ad:be:ef:00:04')
        make_tcp(w, c2_dst, c2_src, dp_c, sp_c, 0x18, beacon)  # symmetric response

    w.close()
    print("\n[+] Done! Generated: test_full_threats.pcap")
    print("    Run:  python run_dpi.py test_full_threats.pcap output_full.pcap")

if __name__ == '__main__':
    main()
