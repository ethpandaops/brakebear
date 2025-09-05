#!/bin/bash

set -euo pipefail

# Source helper functions
source ../helpers.sh

print_header "High Latency Test"

# Check containers
echo "Checking containers..."
check_container "latency-high" || exit 1
check_container "latency-normal" || exit 1
echo "✓ All containers running"
echo ""

# Test latency
print_header "Latency Comparison"
compare_containers "latency-normal" "latency-high" "latency"
echo ""

# Extended latency test for jitter observation
print_header "Extended Latency Test (50 pings)"
echo "=== latency-normal (control) ==="
test_latency "latency-normal" "google.com" 50
echo ""
echo "=== latency-high (500ms latency + 50ms jitter) ==="
test_latency "latency-high" "google.com" 50
echo ""

# Summary
print_header "Test Summary"
echo "The latency-high container should show:"
echo "  - Average latency around 500ms"
echo "  - Jitter (variation) around 50ms"
echo ""
echo "The latency-normal container should show normal latency."
echo ""
echo "Note: Ensure BreakBear is running with:"
echo "  sudo ./breakbear run --config tests/high-latency/breakbear.yaml"