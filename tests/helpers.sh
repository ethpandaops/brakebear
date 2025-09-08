#!/bin/bash

# Common helper functions for test scripts

# Run speedtest in a container
run_speedtest() {
    local container=$1
    echo "Running speedtest on $container..."
    docker exec "$container" speedtest-cli --simple 2>/dev/null || {
        echo "Speedtest failed - network might be limited or unavailable"
        return 1
    }
}

# Test download speed with wget
test_download() {
    local container=$1
    local url=${2:-"http://speedtest.tele2.net/1MB.zip"}
    
    echo "Testing download speed on $container..."
    docker exec "$container" sh -c "time wget -O /dev/null '$url' 2>&1 | grep -E 'real|saved'" || {
        echo "Download test failed"
        return 1
    }
}

# Test latency with ping
test_latency() {
    local container=$1
    local target=${2:-"google.com"}
    local count=${3:-10}
    
    echo "Testing latency on $container (${count} pings to $target)..."
    docker exec "$container" ping -c "$count" -q "$target" 2>/dev/null | grep -E "min/avg/max|packet loss" || {
        echo "Ping test failed"
        return 1
    }
}

# Test packet loss
test_packet_loss() {
    local container=$1
    local target=${2:-"google.com"}
    local count=${3:-100}
    
    echo "Testing packet loss on $container (${count} packets)..."
    docker exec "$container" ping -c "$count" -q "$target" 2>/dev/null | grep "packet loss" || {
        echo "Packet loss test failed"
        return 1
    }
}

# Compare two containers
compare_containers() {
    local container1=$1
    local container2=$2
    local test_type=${3:-"download"}
    
    echo "Comparing $test_type between $container1 and $container2..."
    echo ""
    echo "=== $container1 ==="
    case "$test_type" in
        "speedtest")
            run_speedtest "$container1"
            ;;
        "download")
            test_download "$container1"
            ;;
        "latency")
            test_latency "$container1"
            ;;
        *)
            echo "Unknown test type: $test_type"
            return 1
            ;;
    esac
    
    echo ""
    echo "=== $container2 ==="
    case "$test_type" in
        "speedtest")
            run_speedtest "$container2"
            ;;
        "download")
            test_download "$container2"
            ;;
        "latency")
            test_latency "$container2"
            ;;
    esac
}

# Check if container is running
check_container() {
    local container=$1
    if ! docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        echo "Error: Container '$container' is not running"
        return 1
    fi
    return 0
}

# Print test header with colors
print_header() {
    local test_name=$1
    local color_blue='\033[1;34m'
    local color_cyan='\033[1;36m' 
    local color_reset='\033[0m'
    
    echo -e "${color_blue}========================================${color_reset}"
    echo -e "${color_cyan}$test_name${color_reset}"
    echo -e "${color_blue}========================================${color_reset}"
    echo ""
}