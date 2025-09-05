#!/bin/bash

set -euo pipefail

# Source helper functions
source ../helpers.sh

print_header "Combined Network Limitations Test"

# Check containers
echo "Checking containers..."
check_container "combined-limited" || exit 1
check_container "combined-control" || exit 1
echo "✓ All containers running"
echo ""

# Test all aspects
print_header "1. Bandwidth Test"
echo "=== combined-control (unlimited) ==="
run_speedtest "combined-control"
echo ""
echo "=== combined-limited (1Mbps down, 500kbps up) ==="
run_speedtest "combined-limited"
echo ""

print_header "2. Latency Test"
echo "=== combined-control (normal latency) ==="
test_latency "combined-control" "google.com" 20
echo ""
echo "=== combined-limited (50ms latency, 10ms jitter) ==="
test_latency "combined-limited" "google.com" 20
echo ""

print_header "3. Packet Loss Test"
echo "=== combined-control (no loss) ==="
test_packet_loss "combined-control" "google.com" 50
echo ""
echo "=== combined-limited (0.1% loss) ==="
test_packet_loss "combined-limited" "google.com" 50
echo ""

print_header "4. Real-world Download Test"
echo "Testing download with all limitations combined..."
echo ""
echo "=== combined-control ==="
test_download "combined-control" "http://speedtest.tele2.net/1MB.zip"
echo ""
echo "=== combined-limited ==="
test_download "combined-limited" "http://speedtest.tele2.net/1MB.zip"
echo ""

# Summary
print_header "Test Summary"
echo "The combined-limited container should show:"
echo "  - Download rate: ~1 Mbps"
echo "  - Upload rate: ~500 kbps"
echo "  - Latency: ~50ms added"
echo "  - Jitter: ~10ms variation"
echo "  - Packet loss: ~0.1%"
echo ""
echo "This simulates a poor quality connection with multiple issues."
echo ""
echo "Note: Ensure BreakBear is running with:"
echo "  sudo ./breakbear run --config tests/combined/breakbear.yaml"
