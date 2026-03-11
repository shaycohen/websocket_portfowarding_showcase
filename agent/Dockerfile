# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Copy module definition and source together so go mod tidy can see imports
COPY go.mod main.go ./

# GONOSUMDB=* skips the checksum-database lookup (fine for a PoC).
# go mod tidy downloads the dependency and writes go.sum.
RUN GONOSUMDB='*' go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /agent .

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.21

# Install OpenSSH server, netcat, sudo and shadow utils (usermod)
RUN apk add --no-cache openssh netcat-openbsd sudo shadow

# Generate static SSH host keys
RUN ssh-keygen -A

# Create the sshd privilege-separation directory and sudoers drop-in dir
RUN mkdir -p /run/sshd /etc/sudoers.d && \
    echo '#includedir /etc/sudoers.d' >> /etc/sudoers

COPY sshd_config /etc/ssh/sshd_config
COPY --from=builder /agent /usr/local/bin/agent
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
