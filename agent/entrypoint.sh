#!/bin/sh
set -e

# Start SSH daemon in the background
/usr/sbin/sshd

echo "[entrypoint] sshd started, waiting for it to accept connections..."

# Wait until sshd is listening on port 22 (up to 10 s)
for i in $(seq 1 20); do
    nc -z 127.0.0.1 22 2>/dev/null && break || true
    sleep 0.5
done

echo "[entrypoint] sshd ready, launching agent"

exec /usr/local/bin/agent
