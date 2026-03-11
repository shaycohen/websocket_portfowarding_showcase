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

# Install OpenSSH server and netcat (used in entrypoint wait-loop)
RUN apk add --no-cache openssh netcat-openbsd

# Generate static SSH host keys
RUN ssh-keygen -A

# Create the SSH user; password is set at container start from $SSH_PASS
RUN adduser -D -s /bin/sh user

# Create the sshd privilege-separation directory
RUN mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY --from=builder /agent /usr/local/bin/agent
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
