# BrakeBear Test Scenarios

This directory contains various test scenarios for testing BrakeBear's network traffic control capabilities. Each scenario is isolated in its own directory with specific configurations.

## Directory Structure

```
tests/
├── Dockerfile             # Base image with network testing tools
├── helpers.sh             # Common helper functions
│
├── bandwidth-limit/       # Bandwidth limitation testing
│   ├── docker-compose.yml
│   ├── brakebear.yaml
│   └── test.sh
│
├── high-latency/         # Latency and jitter testing
│   ├── docker-compose.yml
│   ├── brakebear.yaml
│   └── test.sh
│
├── packet-loss/          # Packet loss testing
│   ├── docker-compose.yml
│   ├── brakebear.yaml
│   └── test.sh
│
├── combined/             # All limitations combined
│   ├── docker-compose.yml
│   ├── brakebear.yaml
│   └── test.sh
│
└── unlimited/            # Baseline/control testing
    ├── docker-compose.yml
    ├── brakebear.yaml
    └── test.sh
```

## Test Scenarios

### 1. **bandwidth-limit**
Tests download and upload rate limiting.
- **Containers**: `bandwidth-limited`, `bandwidth-unlimited`
- **Limits**: 1Mbps download, 500kbps upload
- **Use Case**: Verify bandwidth throttling works correctly

### 2. **high-latency**
Tests network latency and jitter injection.
- **Containers**: `latency-high`, `latency-normal`
- **Limits**: 500ms latency, 50ms jitter
- **Use Case**: Simulate high-latency connections (satellite, cross-continental)

### 3. **packet-loss**
Tests packet loss simulation.
- **Containers**: `loss-high`, `loss-none`
- **Limits**: 5% packet loss
- **Use Case**: Simulate unreliable network conditions

### 4. **combined**
Tests all network limitations together.
- **Containers**: `combined-limited`, `combined-control`
- **Limits**: 1Mbps down, 500kbps up, 50ms latency, 10ms jitter, 0.1% loss
- **Use Case**: Simulate realistic poor network conditions

### 5. **unlimited**
Baseline containers with no limitations.
- **Containers**: `unlimited-1`, `unlimited-2`
- **Limits**: None
- **Use Case**: Control group for performance comparison

## Usage

### Quick Start

```bash
# Build the test image (one time)
make test-build-image
# By default will start the combined test scenario
make test-up
make test-run-brakebear # Open this in a new terminal to see the BrakeBear logs
make test-script # Runs the test script for the combined test scenario
make test-down-all
```

Altneratively you can also target single testing scenarios:
```bash
# Start a specific test scenario
make test-up TEST=bandwidth-limit
make test-up TEST=high-latency
make test-up TEST=combined  # default

# Run BrakeBear with the test configuration
make test-run-brakebear TEST=bandwidth-limit

# Run test script for a specific scenario
make test-script TEST=bandwidth-limit
make test-script TEST=combined

# Stop a specific test
make test-down TEST=bandwidth-limit

# Clean up everything
make test-cleanup
```

### Working with Multiple Scenarios

```bash
# Start all test scenarios
make test-up-all

# Run test scripts for all scenarios
make test-script TEST=bandwidth-limit
make test-script TEST=high-latency
make test-script TEST=packet-loss
make test-script TEST=combined
make test-script TEST=unlimited

# Stop all test scenarios
make test-down-all
```

### Manual Testing

```bash
# Start containers for a scenario
cd tests/bandwidth-limit
docker compose up -d

# Apply BrakeBear limits
sudo ./brakebear run --config tests/bandwidth-limit/brakebear.yaml

# Test with speedtest
docker exec bandwidth-limited speedtest-cli
docker exec bandwidth-unlimited speedtest-cli

# Compare results to see limiting in action
```

## Test Tools Available

Each container includes:
- **speedtest-cli** - Measure internet bandwidth
- **iperf3** - Network performance testing
- **curl/wget** - HTTP transfer testing
- **ping** - Latency and packet loss testing
- **dig/nslookup** - DNS testing
- **tc/ip** - Traffic control inspection
- **netstat/ss** - Network statistics

## Testing Commands

### Bandwidth Testing
```bash
# Speedtest
docker exec <container> speedtest-cli

# Download test
docker exec <container> wget --report-speed=bits --show-progress -O /dev/null http://speedtest.tele2.net/10MB.zip

# iperf3 (requires server)
docker exec <container> iperf3 -c <server-ip>
```

### Latency Testing
```bash
# Ping test
docker exec <container> ping -c 10 google.com

# Continuous ping with statistics
docker exec <container> ping -i 0.2 google.com
```

### Packet Loss Testing
```bash
# Extended ping to detect loss
docker exec <container> ping -c 100 -q google.com
```

### Verify Traffic Control
```bash
# Check if rules are applied
docker exec <container> tc qdisc show
docker exec <container> tc class show
```


## Troubleshooting

### Containers not starting
```bash
# Check Docker Compose logs
cd tests/<scenario>
docker compose logs

# Verify network exists
docker network ls | grep brakebear-test
```

### BrakeBear not applying limits
- Ensure running with sudo (required for netns operations)
- Check container is in the configuration file
- Verify container names match exactly
- Check BrakeBear logs for errors

### Test results inconsistent
- Ensure only one test scenario is running at a time
- Verify BrakeBear is running before testing
- Allow time for limits to be applied after container start
- Check host network isn't saturated

## Adding New Test Scenarios

1. Create a new directory: `tests/my-test/`
2. Add `docker-compose.yml` with test containers
3. Add `brakebear.yaml` with limit configuration
4. Containers should use `build: context: ..`
5. Use the shared network: `brakebear-test`

Example:
```yaml
# tests/my-test/docker-compose.yml
services:
  my-test-container:
    build:
      context: ..
      dockerfile: Dockerfile
    image: brakebear-test:latest
    container_name: my-test-container
    networks:
      - brakebear-test

networks:
  brakebear-test:
    driver: bridge
    name: brakebear-test
```
