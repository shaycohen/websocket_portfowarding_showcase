# Use a slim Debian-based image so native npm modules (ssh2/cpu-features) compile
FROM node:22-slim

WORKDIR /app

# Install build tools needed for optional native addons in ssh2
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public/ ./public/

EXPOSE 3000

# Run as non-root
USER node

CMD ["node", "server.js"]
