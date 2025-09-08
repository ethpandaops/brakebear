FROM alpine:latest

# Install required packages and speedtest-cli
RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    wget \
    iperf3 \
    net-tools \
    iproute2 \
    bind-tools \
    busybox-extras \
    && pip3 install --no-cache-dir speedtest-cli --break-system-packages

# Create a simple entrypoint that keeps the container running
ENTRYPOINT ["/bin/sh", "-c", "trap : TERM INT; sleep infinity & wait"]