<div align="center">
  <img src="assets/logo-wide.jpg" alt="BrakeBear Logo" width="1650"/>
</div>


**BrakeBear** applies network bandwidth limits, latency, jitter, and packet loss to Docker containers using Linux traffic control (tc) and network namespaces.

## Features

- **Bandwidth limiting**: Upload and download rate limits
- **Network emulation**: Latency, jitter, and packet loss simulation
- **Docker integration**: Automatic container discovery and monitoring
- **IPv6 & dual-stack support**: Full support for IPv4, IPv6, and mixed networks
- **Smart exclusions**: Bypass traffic limits for specific networks, IPs, ports, or Docker networks
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
       private-networks: true # Excludes RFC1918 private networks and IPv6 ULA/Link-Local from traffic limiting
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
Exclude RFC1918 private networks and IPv6 private ranges:
- IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- IPv6: `fc00::/7` (ULA), `fe80::/10` (Link-Local)

```yaml
exclusions:
  private-networks: true
```

#### CIDR Ranges
Exclude specific IP ranges using CIDR notation (supports both IPv4 and IPv6):
```yaml
exclusions:
  cidr:
    ranges:
      # IPv4 ranges
      - "192.168.1.0/24"
      - "10.0.0.0/8"
      - "203.0.113.0/24"
      # IPv6 ranges
      - "2001:db8::/32"          # IPv6 documentation range
      - "fc00::/7"               # IPv6 ULA
      - "2001:db8::1/128"        # Specific IPv6 host
```

#### DNS-Based Exclusions
Exclude traffic to specific hostnames (with automatic IPv4/IPv6 resolution):
```yaml
exclusions:
  dns:
    names:
      - "api.github.com"         # Resolves to both IPv4 and IPv6
      - "registry.npmjs.org"     # Dual-stack hostname
      - "ipv6.google.com"        # IPv6-preferred hostname
    check_interval: "10m"  # How often to re-resolve DNS (optional, default: 5m)
```

#### Port-Based Exclusions
Exclude traffic to specific ports regardless of destination (applies to both IPv4 and IPv6):
```yaml
exclusions:
  ports:
    tcp: ["80", "443", "8000-9000"]    # TCP ports and ranges
    udp: ["53", "5353", "546-547"]     # UDP ports (includes DHCPv6)
```

#### Docker Network Exclusions
Exclude traffic on specific Docker networks (automatically discovers IPv4/IPv6 CIDR ranges):
```yaml
exclusions:
  docker-networks:
    names: ["shared-network"]  # Specific network names
```

Exclude traffic on all Docker bridge networks using wildcard:
```yaml
exclusions:
  docker-networks:
    names: ["*"]  # All bridge networks (IPv4 and IPv6)
```



#### Combined Exclusions
Multiple exclusion types can be used together for comprehensive dual-stack support:
```yaml
exclusions:
  private-networks: true  # IPv4 RFC1918 + IPv6 ULA/Link-Local
  cidr:
    ranges:
      - "203.0.113.0/24"    # IPv4 documentation range
      - "2001:db8::/32"     # IPv6 documentation range
  dns:
    names: ["dual-stack.example.com"]  # Resolves to both IPv4 and IPv6
    check_interval: "5m"
  ports:
    tcp: ["80", "443"]
    udp: ["53", "546-547"]  # DNS + DHCPv6
  docker-networks:
    names: ["bridge"]
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
