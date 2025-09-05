#!/bin/bash

set -euo pipefail

# Source helper functions
source ../helpers.sh

print_header "Unlimited/Baseline Test"

# Check containers
echo "Checking containers..."
check_container "unlimited-1" || exit 1
check_container "unlimited-2" || exit 1
echo "✓ All containers running"
echo ""

# Test baseline performance
print_header "Baseline Performance Test"
echo "These containers have no limitations applied."
echo "Use these results as a baseline for comparison."
echo ""

echo "=== unlimited-1 ==="
run_speedtest "unlimited-1"
echo ""
test_latency "unlimited-1" "google.com" 10
echo ""

echo "=== unlimited-2 ==="
run_speedtest "unlimited-2"
echo ""
test_latency "unlimited-2" "google.com" 10
echo ""

# Test consistency between containers
print_header "Consistency Check"
echo "Both containers should show similar results..."
echo ""
echo "Download test comparison:"
test_download "unlimited-1"
test_download "unlimited-2"
echo ""

# Summary
print_header "Test Summary"
echo "Both unlimited containers should show:"
echo "  - Maximum available bandwidth"
echo "  - Minimal latency (network dependent)"
echo "  - 0% packet loss"
echo ""
echo "Use these results to compare against limited containers."
echo ""
echo "Note: No BreakBear configuration needed for these containers."