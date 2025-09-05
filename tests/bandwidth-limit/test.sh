#!/bin/bash
set -euo pipefail

# Source helper functions
source ../helpers.sh

print_header "Bandwidth Limit Test"

# Check containers
echo "Checking containers..."
check_container "bandwidth-limited" || exit 1
check_container "bandwidth-unlimited" || exit 1
echo "✓ All containers running"
echo ""

# Test bandwidth with speedtest
print_header "Speedtest Comparison"
compare_containers "bandwidth-unlimited" "bandwidth-limited" "speedtest"
echo ""

# Test download speeds
print_header "Download Speed Comparison"
compare_containers "bandwidth-unlimited" "bandwidth-limited" "download"
echo ""

# Summary
print_header "Test Summary"
echo "The bandwidth-limited container should show:"
echo "  - Download rate around 1 Mbps"
echo "  - Upload rate around 500 kbps"
echo ""
echo "The bandwidth-unlimited container should show full speed."
echo ""
echo "Note: Ensure BreakBear is running with:"
echo "  sudo ./breakbear run --config tests/bandwidth-limit/breakbear.yaml"
