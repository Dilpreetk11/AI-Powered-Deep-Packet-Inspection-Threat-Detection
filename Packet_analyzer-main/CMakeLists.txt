cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─────────────────────────────────────────────────────────────────────────────
# Platform-specific compiler flags
# ─────────────────────────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W3 /wd4244 /wd4267 /wd4996)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Include paths
# ─────────────────────────────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ─────────────────────────────────────────────────────────────────────────────
# Core DPI library sources (shared across all targets)
# ─────────────────────────────────────────────────────────────────────────────
set(CORE_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# AI subsystem sources
# ─────────────────────────────────────────────────────────────────────────────
set(AI_SOURCES
    src/feature_extractor.cpp
    src/ml_classifier.cpp
    src/anomaly_detector.cpp
    src/threat_scorer.cpp
    src/ai_engine.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# Full engine sources (modular DPI engine with connection tracking)
# ─────────────────────────────────────────────────────────────────────────────
set(ENGINE_SOURCES
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# Target 1: dpi_engine — Full AI-enhanced DPI engine (modular architecture)
# ─────────────────────────────────────────────────────────────────────────────
add_executable(dpi_engine
    ${CORE_SOURCES}
    ${AI_SOURCES}
    ${ENGINE_SOURCES}
    src/main_dpi.cpp
)
target_compile_definitions(dpi_engine PRIVATE DPI_ENABLE_AI=1)

# ─────────────────────────────────────────────────────────────────────────────
# Target 2: dpi_mt — Multi-threaded standalone DPI (self-contained, with AI)
# ─────────────────────────────────────────────────────────────────────────────
add_executable(dpi_mt
    ${CORE_SOURCES}
    ${AI_SOURCES}
    src/dpi_mt.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# Target 3: packet_analyzer — Simple packet analyzer (legacy)
# ─────────────────────────────────────────────────────────────────────────────
add_executable(packet_analyzer
    src/main_simple.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# Thread support (required for multi-threaded engine)
# ─────────────────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine    PRIVATE Threads::Threads)
target_link_libraries(dpi_mt        PRIVATE Threads::Threads)

# ─────────────────────────────────────────────────────────────────────────────
# Windows: link ws2_32 if needed
# ─────────────────────────────────────────────────────────────────────────────
if(WIN32)
    target_link_libraries(dpi_engine    PRIVATE ws2_32)
    target_link_libraries(dpi_mt        PRIVATE ws2_32)
    target_link_libraries(packet_analyzer PRIVATE ws2_32)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# macOS / Linux extras
# ─────────────────────────────────────────────────────────────────────────────
if(APPLE)
    # macOS-specific settings if needed
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Install rules
# ─────────────────────────────────────────────────────────────────────────────
install(TARGETS dpi_engine dpi_mt packet_analyzer RUNTIME DESTINATION bin)

message(STATUS "")
message(STATUS "-- PacketAnalyzer v2.0  |  AI-Enhanced DPI Engine")
message(STATUS "   Targets: dpi_engine | dpi_mt | packet_analyzer")
message(STATUS "")
