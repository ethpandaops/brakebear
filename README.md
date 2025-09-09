# Brake Bear


BrakeBear applies network bandwidth limits, latency, jitter, and packet loss to Docker containers using Linux traffic control (tc) and network namespaces.

<div align="center">
  <img src="assets/logo.jpg" alt="BrakeBear Logo" width="300"/>
</div>

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
     exclude_networks:
       - type: "private-ranges"
   ```

For more examples, see the [example config file](brakebear.yaml).

**Run it using docker:**
```bash
docker run --rm -it \
  --privileged \
  --network host \
  --pid host \
  --name brakebear \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/brakebear.yaml:/etc/brakebear/brakebear.yaml \
  ghcr.io/ethpandaops/brakebear:master
```
Or build it from the source code:
1. **Build BrakeBear**:
   ```bash
   make build
   ```

2. **Run BrakeBear**:
   ```bash
   sudo ./brakebear run --config brakebear.yaml
   ```

> **Note**: The `--privileged`, `--network host`, and `--pid host` flags are required for BrakeBear to access container network namespaces and apply traffic control rules.

## Configuration

### Rate Limits
- `download_rate`: Ingress bandwidth limit (e.g., `1Mbps`, `500kbps`)
- `upload_rate`: Egress bandwidth limit (e.g., `1Mbps`, `500kbps`)

### Network Emulation
- `latency`: Base latency (e.g., `50ms`, `100ms`)
- `jitter`: Latency variation (e.g., `10ms`, `20ms`)
- `loss`: Packet loss percentage (e.g., `0.1%`, `5%`)

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
