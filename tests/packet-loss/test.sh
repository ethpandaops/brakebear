#!/bin/bash

set -euo pipefail

# Source helper functions
source ../helpers.sh

print_header "Packet Loss Test"

# Check containers
echo "Checking containers..."
check_container "loss-high" || exit 1
check_container "loss-none" || exit 1
echo "✓ All containers running"
echo ""

# Test packet loss with extended ping
print_header "Packet Loss Test (100 packets)"
echo "=== loss-none (control) ==="
test_packet_loss "loss-none" "google.com" 100
echo ""
echo "=== loss-high (5% packet loss) ==="
test_packet_loss "loss-high" "google.com" 100
echo ""

# Test impact on downloads
print_header "Download Reliability Test"
echo "Testing multiple small downloads to observe failures..."
echo ""
echo "=== loss-none (should succeed all) ==="
for i in {1..10}; do
    echo -n "Attempt $i: "
    docker exec loss-none wget -q -O /dev/null --timeout=5 http://google.com && echo "✓ Success" || echo "✗ Failed"
done
echo ""

echo "=== loss-high (should see some failures) ==="
for i in {1..10}; do
    echo -n "Attempt $i: "
    docker exec loss-high wget -q -O /dev/null --timeout=5 http://google.com && echo "✓ Success" || echo "✗ Failed"
done
echo ""

# Summary
print_header "Test Summary"
echo "The loss-high container should show:"
echo "  - Approximately 5% packet loss"
echo "  - Some download attempts failing"
echo ""
echo "The loss-none container should show:"
echo "  - 0% or near 0% packet loss"
echo "  - All download attempts succeeding"
echo ""
echo "Note: Ensure BrakeBear is running with:"
echo "  sudo ./brakebear run --config tests/packet-loss/brakebear.yaml"
