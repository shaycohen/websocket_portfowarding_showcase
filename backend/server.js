'use strict';

const http = require('http');
const net = require('net');
const path = require('path');
const { execSync } = require('child_process');
const { randomBytes } = require('crypto');
const fs = require('fs');
const os = require('os');

const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');
const { Client: SshClient } = require('ssh2');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT ?? '3000', 10);
const AGENT_TIMEOUT_MS = parseInt(process.env.AGENT_TIMEOUT_MS ?? '10000', 10);

// ── App setup ─────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

// ── Credential generation ─────────────────────────────────────────────────────
/**
 * Generates a temporary SSH user credential set:
 *   - username:   short, sanitised, unique
 *   - publicKey:  Ed25519 public key in OpenSSH authorized_keys format
 *   - privateKey: Ed25519 private key in PEM format (used by ssh2 client)
 *   - shadowHash: SHA-512 crypt(3) hash ($6$…) for direct /etc/shadow insertion
 */
function generateSSHCredentials(agentId) {
  const sanitized = agentId.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 10);
  const suffix = randomBytes(3).toString('hex');
  const username = `tmp_${sanitized}_${suffix}`;

  // Generate Ed25519 key pair via ssh-keygen
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sshcred-'));
  const keyPath = path.join(tmpDir, 'id_ed25519');
  try {
    execSync(`ssh-keygen -t ed25519 -f "${keyPath}" -N "" -q`);
    const privateKey = fs.readFileSync(keyPath, 'utf8');
    const publicKey = fs.readFileSync(`${keyPath}.pub`, 'utf8').trim();

    // Generate a random password, keep it for the admin UI, and produce a
    // SHA-512 shadow hash ($6$…) so the agent never receives the plaintext.
    const plainPassword = randomBytes(16).toString('hex');
    const shadowHash = execSync(`openssl passwd -6 "${plainPassword}"`).toString().trim();

    return { username, publicKey, privateKey, shadowHash, plainPassword };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ── Agent state ───────────────────────────────────────────────────────────────
/**
 * Map<agentId, AgentState>
 *
 * AgentState {
 *   id:               string
 *   lastSeen:         number          – epoch ms of last poll
 *   status:           'idle' | 'forward-requested' | 'tunneling'
 *   sshCredentials:   object | null   – { username, publicKey, privateKey, shadowHash }
 *   tunnelWs:         WebSocket | null
 *   tcpServer:        net.Server | null
 *   tcpPort:          number | null   – ephemeral port used by ssh2
 *   currentTcpSocket: net.Socket | null
 * }
 */
const agents = new Map();

function upsertAgent(id) {
  if (!agents.has(id)) {
    agents.set(id, {
      id,
      lastSeen: Date.now(),
      status: 'idle',
      sshCredentials: null,
      tunnelWs: null,
      tcpServer: null,
      tcpPort: null,
      currentTcpSocket: null,
    });
  }
  return agents.get(id);
}

function isActive(agent) {
  return Date.now() - agent.lastSeen < AGENT_TIMEOUT_MS;
}

function cleanupTunnel(agent) {
  if (agent.currentTcpSocket) {
    agent.currentTcpSocket.destroy();
    agent.currentTcpSocket = null;
  }
  if (agent.tcpServer) {
    agent.tcpServer.close();
    agent.tcpServer = null;
    agent.tcpPort = null;
  }
  if (agent.tunnelWs?.readyState === WebSocket.OPEN) {
    agent.tunnelWs.close();
  }
  agent.tunnelWs = null;
  agent.sshCredentials = null;
}

// ── HTTP endpoints ─────────────────────────────────────────────────────────────

// Agent heartbeat / command poll
app.post('/api/agents/:id/poll', (req, res) => {
  const agent = upsertAgent(req.params.id);
  agent.lastSeen = Date.now();

  if (agent.status === 'forward-requested' && agent.sshCredentials) {
    // Send 'forward' with the temporary credentials the agent needs to set up
    // its local SSH user.  The private key stays on the backend only.
    const { username, publicKey, shadowHash } = agent.sshCredentials;
    res.json({ action: 'forward', username, publicKey, shadowHash });
  } else {
    res.json({ action: 'pong' });
  }
});

// Admin: list currently-active agents
app.get('/api/agents', (req, res) => {
  const list = [];
  for (const agent of agents.values()) {
    if (isActive(agent)) {
      list.push({ id: agent.id, status: agent.status, lastSeen: agent.lastSeen });
    }
  }
  res.json(list);
});

// Admin: fetch a single agent's state
app.get('/api/agents/:id', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent || !isActive(agent)) {
    return res.status(404).json({ error: 'Agent not found or offline' });
  }
  res.json({ id: agent.id, status: agent.status, lastSeen: agent.lastSeen });
});

// Admin: ask an agent to set up the SSH port-forward tunnel
app.post('/api/agents/:id/connect', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent || !isActive(agent)) {
    return res.status(404).json({ error: 'Agent not found or offline' });
  }
  if (agent.status === 'idle') {
    agent.sshCredentials = generateSSHCredentials(agent.id);
    agent.status = 'forward-requested';
    console.log(`[connect] generated credentials for agent ${agent.id}, user=${agent.sshCredentials.username}`);
  }
  res.json({ status: agent.status });
});

// Admin: tear down an active tunnel
app.post('/api/agents/:id/disconnect', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  cleanupTunnel(agent);
  agent.status = 'idle';
  res.json({ success: true });
});

// ── WebSocket upgrade dispatcher ──────────────────────────────────────────────
server.on('upgrade', (req, socket, head) => {
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);

  if (pathname.startsWith('/ws/tunnel/')) {
    const agentId = pathname.slice('/ws/tunnel/'.length);
    wss.handleUpgrade(req, socket, head, (ws) => handleAgentTunnel(agentId, ws));
  } else if (pathname.startsWith('/ws/terminal/')) {
    const agentId = pathname.slice('/ws/terminal/'.length);
    wss.handleUpgrade(req, socket, head, (ws) => handleAdminTerminal(agentId, ws));
  } else {
    socket.destroy();
  }
});

// ── Agent tunnel WebSocket handler ────────────────────────────────────────────
/**
 * Called when the agent connects its WS tunnel.
 *
 * Creates an ephemeral local TCP server. When ssh2 (in handleAdminTerminal)
 * connects to that TCP server, data is relayed through the WS to the agent,
 * which forwards it to its local sshd.
 *
 * Single-session design: only one TCP client at a time. A new connection
 * replaces the previous one.
 */
function handleAgentTunnel(agentId, ws) {
  const agent = agents.get(agentId);
  if (!agent) {
    console.log(`[tunnel] rejected unknown agent: ${agentId}`);
    ws.close(1008, 'Unknown agent');
    return;
  }

  console.log(`[tunnel] agent ${agentId} WS connected`);
  agent.tunnelWs = ws;

  // Buffer WS frames from the agent that arrive before ssh2 connects.
  //
  // Root-cause: the agent dials local sshd immediately on WS connect, so sshd's
  // opening banner arrives here before the ephemeral TCP server has accepted any
  // client.  Without buffering, that banner is dropped and the SSH handshake
  // never completes ("Timed out while waiting for handshake").
  let pendingFromAgent = [];

  // WS → TCP: data from agent (sshd responses) → ssh2 client socket
  ws.on('message', (data) => {
    if (agent.currentTcpSocket && !agent.currentTcpSocket.destroyed) {
      agent.currentTcpSocket.write(data);
    } else {
      // No TCP client yet – buffer until one connects
      pendingFromAgent.push(data);
    }
  });

  // Local TCP server: ssh2 connects here, we bridge to the WS
  const tcpServer = net.createServer((socket) => {
    console.log(`[tunnel] TCP connection for agent ${agentId}`);

    // Replace any existing socket
    if (agent.currentTcpSocket) {
      agent.currentTcpSocket.destroy();
    }
    agent.currentTcpSocket = socket;

    // Flush any sshd data that arrived before this TCP client connected
    if (pendingFromAgent.length) {
      console.log(`[tunnel] flushing ${pendingFromAgent.length} buffered frame(s) to ssh2`);
      for (const chunk of pendingFromAgent) socket.write(chunk);
      pendingFromAgent = [];
    }

    // TCP → WS: data from ssh2 → agent → sshd
    socket.on('data', (chunk) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(chunk);
      }
    });

    socket.on('close', () => {
      if (agent.currentTcpSocket === socket) {
        agent.currentTcpSocket = null;
      }
    });

    socket.on('error', (err) => {
      console.error(`[tunnel] TCP socket error (${agentId}): ${err.message}`);
    });
  });

  // Bind to an OS-assigned ephemeral port, loopback only
  tcpServer.listen(0, '127.0.0.1', () => {
    const { port } = tcpServer.address();
    agent.tcpPort = port;
    agent.tcpServer = tcpServer;
    agent.status = 'tunneling';
    console.log(`[tunnel] agent ${agentId} relay listening on 127.0.0.1:${port}`);
  });

  tcpServer.on('error', (err) => {
    console.error(`[tunnel] TCP server error (${agentId}): ${err.message}`);
  });

  ws.on('close', () => {
    console.log(`[tunnel] agent ${agentId} WS closed`);
    pendingFromAgent = [];
    if (agent.tcpServer) {
      agent.tcpServer.close();
      agent.tcpServer = null;
      agent.tcpPort = null;
    }
    if (agent.currentTcpSocket) {
      agent.currentTcpSocket.destroy();
      agent.currentTcpSocket = null;
    }
    agent.tunnelWs = null;
    agent.status = 'idle';
  });

  ws.on('error', (err) => {
    console.error(`[tunnel] WS error (${agentId}): ${err.message}`);
  });
}

// ── Admin terminal WebSocket handler ──────────────────────────────────────────
/**
 * Called when an admin browser connects to open a terminal.
 *
 * Waits up to 30 s for the tunnel to become ready, then uses ssh2 to open an
 * interactive shell through the local TCP relay → WS tunnel → agent sshd.
 *
 * Protocol (JSON framed):
 *   Server → Client:
 *     { type: 'status', status: 'connecting'|'ready'|'error', message: string }
 *     { type: 'data',   data: '<base64>' }   – raw terminal bytes
 *
 *   Client → Server:
 *     { type: 'input',  data: '<base64>' }   – keystrokes
 *     { type: 'resize', rows: number, cols: number }
 */
function handleAdminTerminal(agentId, ws) {
  const agent = agents.get(agentId);

  const send = (obj) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  };

  if (!agent) {
    send({ type: 'status', status: 'error', message: 'Agent not found' });
    ws.close();
    return;
  }

  let stream = null;
  let ssh = null;
  let closed = false;

  // Clean up when the admin closes the browser tab / modal
  ws.on('close', () => {
    closed = true;
    if (stream) stream.end();
    if (ssh) ssh.end();
  });

  ws.on('error', (err) => {
    console.error(`[terminal] WS error (${agentId}): ${err.message}`);
  });

  // Poll until the tunnel is ready, then SSH in
  const MAX_ATTEMPTS = 60;   // 30 s @ 500 ms
  let attempts = 0;

  function tryConnect() {
    if (closed || ws.readyState !== WebSocket.OPEN) return;

    if (agent.status !== 'tunneling' || !agent.tcpPort) {
      attempts++;
      if (attempts >= MAX_ATTEMPTS) {
        send({ type: 'status', status: 'error', message: 'Timed out waiting for tunnel' });
        ws.close();
        return;
      }
      send({ type: 'status', status: 'connecting', message: `Waiting for agent tunnel… (${attempts}/${MAX_ATTEMPTS})` });
      setTimeout(tryConnect, 500);
      return;
    }

    if (!agent.sshCredentials) {
      send({ type: 'status', status: 'error', message: 'No SSH credentials available' });
      ws.close();
      return;
    }

    // Tunnel is live – open SSH session through it using the temp user's private key
    ssh = new SshClient();

    ssh.on('ready', () => {
      console.log(`[terminal] SSH ready for agent ${agentId}`);
      send({
        type: 'status',
        status: 'ready',
        message: 'SSH session established',
        sudoPassword: agent.sshCredentials.plainPassword,
      });

      ssh.shell({ term: 'xterm-256color', rows: 24, cols: 80 }, (err, s) => {
        if (err) {
          send({ type: 'status', status: 'error', message: `Shell error: ${err.message}` });
          ws.close();
          ssh.end();
          return;
        }

        stream = s;

        s.on('data', (chunk) => {
          send({ type: 'data', data: chunk.toString('base64') });
        });

        s.stderr.on('data', (chunk) => {
          send({ type: 'data', data: chunk.toString('base64') });
        });

        s.on('close', () => {
          ws.close();
          ssh.end();
        });
      });
    });

    ssh.on('error', (err) => {
      console.error(`[terminal] SSH error (${agentId}): ${err.message}`);
      send({ type: 'status', status: 'error', message: `SSH error: ${err.message}` });
      ws.close();
    });

    // Handle messages from the browser terminal
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (!stream) return;

        if (msg.type === 'input') {
          stream.write(Buffer.from(msg.data, 'base64'));
        } else if (msg.type === 'resize') {
          // rows, cols, vpixels, hpixels
          stream.setWindow(msg.rows, msg.cols, 0, 0);
        }
      } catch {
        // ignore malformed messages
      }
    });

    // PoC only: skip host-key verification (the host key changes on every
    // container restart anyway)
    ssh.connect({
      host: '127.0.0.1',
      port: agent.tcpPort,
      username: agent.sshCredentials.username,
      privateKey: agent.sshCredentials.privateKey,
      readyTimeout: 10_000,
      hostVerifier: () => true,
    });
  }

  tryConnect();
}

// ── Start ─────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`[backend] listening on http://localhost:${PORT}`);
});
