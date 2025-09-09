<div align="center">
  <img src="assets/logo-wide.jpg" alt="BrakeBear Logo" width="1650"/>
</div>


**BrakeBear** applies network bandwidth limits, latency, jitter, and packet loss to Docker containers using Linux traffic control (tc) and network namespaces.

## Features

- **Bandwidth limiting**: Upload and download rate limits
- **Network emulation**: Latency, jitter, and packet loss simulation
- **Docker integration**: Automatic container discovery and monitoring
- **Real-time application**: Apply limits to running containers
- **Clean removal**: Automatically removes limits when containers stop

## Quick Start



**Create configuration** (`brakebear.yaml`):
   ```yaml
   log_level: "info"
   docker_containers:
   - name: "my-container"
     download_rate: 1mbps
     upload_rate: 500kbps
     latency: 50ms
     jitter: 10ms
     loss: 0.1%
     exclusions:
       private-networks: true # Excludes RFC1918 private networks from traffic limiting
   ```

For more examples, see the [example config file](brakebear.yaml).

**Run it using docker:**
```bash
docker run --rm -it \
  --privileged \
  --network host \
  --pid host \
  --name brakebear \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/brakebear.yaml:/etc/brakebear/brakebear.yaml:ro \
  ghcr.io/ethpandaops/brakebear:master
```
> **Note**: The `--privileged`, `--network host`, and `--pid host` flags are required for BrakeBear to access container network namespaces and apply traffic control rules.

Or build it from the source code:
1. **Build BrakeBear**:
   ```bash
   make build
   ```

2. **Run BrakeBear**:
   ```bash
   sudo ./brakebear run --config brakebear.yaml
   ```

## Configuration

### Rate Limits
- `download_rate`: Ingress bandwidth limit (e.g., `1Mbps`, `500kbps`)
- `upload_rate`: Egress bandwidth limit (e.g., `1Mbps`, `500kbps`)

### Network Emulation
- `latency`: Base latency (e.g., `50ms`, `100ms`)
- `jitter`: Latency variation (e.g., `10ms`, `20ms`)
- `loss`: Packet loss percentage (e.g., `0.1%`, `5%`)

### Network Exclusions
BrakeBear supports excluding specific networks from traffic control rules. By default, no exclusions are applied. The following exclusion types can also be combined:

#### Private Networks
Exclude RFC1918 private networks `(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)`:
```yaml
exclusions:
  private-networks: true
```

#### CIDR Ranges
Exclude specific IP ranges using CIDR notation:
```yaml
exclusions:
  cidr:
    ranges:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
      - "203.0.113.0/24"
```

#### DNS-Based Exclusions
Exclude traffic to specific hostnames (with automatic IP resolution):
```yaml
exclusions:
  dns:
    names:
      - "api.github.com"
      - "registry.npmjs.org"
      - "cdn.jsdelivr.net"
    check_interval: "10m"  # How often to re-resolve DNS (optional, default: 5m)
```

#### Port-Based Exclusions
Exclude traffic to specific ports regardless of destination:
```yaml
exclusions:
  ports:
    tcp: ["80", "443", "8000-9000"]    # TCP ports and ranges
    udp: ["53", "5353"]                # UDP ports
```

#### Combined Exclusions
Multiple exclusion types can be used together:
```yaml
exclusions:
  private-networks: true
  cidr:
    ranges: ["203.0.113.0/24"]
  dns:
    names: ["speedtest.example.com"]
    check_interval: "5m"
  ports:
    tcp: ["80", "443"]
    udp: ["53"]
```

## Requirements

- Linux with `tc` (traffic control) support
- Docker
- Root privileges (for network namespace access)

## How it Works

BrakeBear uses Linux traffic control mechanisms:
- **HTB (Hierarchical Token Bucket)** for bandwidth shaping
- **IFB (Intermediate Functional Block)** interfaces for ingress limiting
- **Netem** for network emulation (latency, jitter, loss)
- **Network namespaces** to apply limits per container


## Development

###
### macOS

To develop on macOS, you can use a [OrbStack VM](https://orbstack.dev/). To create the VM, run:
```bash
make orbstack-dev
```

To clean up the VM, run:
```bash
make orbstack-dev-clean
```

To connect to the VM, run:
```bash
ssh brakebear@orb
```

## License

This project is licensed under the [GNU GPL-3.0](LICENSE).
