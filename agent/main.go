package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	backendURL := envOr("BACKEND_URL", "http://backend:3000")
	agentID := envOr("AGENT_ID", "agent-1")
	sshAddr := envOr("SSH_ADDR", "127.0.0.1:22")

	intervalMS, _ := strconv.Atoi(envOr("POLL_INTERVAL_MS", "1000"))
	pollInterval := time.Duration(intervalMS) * time.Millisecond

	log.Printf("[agent] id=%s backend=%s poll=%v ssh=%s", agentID, backendURL, pollInterval, sshAddr)

	var tunneling atomic.Bool

	for {
		result := poll(backendURL, agentID)

		if result.Action == "forward" && tunneling.CompareAndSwap(false, true) {
			log.Printf("[agent] received 'forward', setting up SSH user and starting tunnel")
			creds := result // capture for goroutine
			go func() {
				defer tunneling.Store(false)
				if err := setupSSHUser(creds.Username, creds.PublicKey, creds.ShadowHash); err != nil {
					log.Printf("[agent] user setup failed: %v", err)
					return
				}
				if err := runTunnel(backendURL, agentID, sshAddr); err != nil {
					log.Printf("[tunnel] closed: %v", err)
				}
			}()
		}

		time.Sleep(pollInterval)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type pollResult struct {
	Action     string `json:"action"`
	Username   string `json:"username"`
	PublicKey  string `json:"publicKey"`
	ShadowHash string `json:"shadowHash"`
}

// poll calls the backend's poll endpoint and returns the full result.
func poll(backendURL, agentID string) pollResult {
	endpoint := backendURL + "/api/agents/" + agentID + "/poll"
	resp, err := http.Post(endpoint, "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		log.Printf("[poll] error: %v", err)
		return pollResult{Action: "pong"}
	}
	defer resp.Body.Close()

	var pr pollResult
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		log.Printf("[poll] decode error: %v", err)
		return pollResult{Action: "pong"}
	}

	if pr.Action != "pong" {
		log.Printf("[poll] action=%s", pr.Action)
	}
	return pr
}

// setupSSHUser creates a temporary OS user, installs the public key, sets the
// shadow-format hashed password, and grants passworded sudo access.
func setupSSHUser(username, publicKey, shadowHash string) error {
	// Create the user (no password, login shell /bin/sh)
	if out, err := exec.Command("adduser", "-D", "-s", "/bin/sh", username).CombinedOutput(); err != nil {
		return fmt.Errorf("adduser %s: %w\n%s", username, err, out)
	}
	log.Printf("[setup] created user %s", username)

	// Create .ssh directory
	sshDir := filepath.Join("/home", username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("mkdir .ssh: %w", err)
	}

	// Write authorized_keys
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, []byte(publicKey+"\n"), 0600); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}

	// Fix ownership so sshd accepts the key
	if out, err := exec.Command("chown", "-R", username+":"+username, sshDir).CombinedOutput(); err != nil {
		return fmt.Errorf("chown .ssh: %w\n%s", err, out)
	}

	// Set the pre-hashed shadow password directly (avoids transmitting plaintext)
	if out, err := exec.Command("usermod", "-p", shadowHash, username).CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -p: %w\n%s", err, out)
	}
	log.Printf("[setup] set shadow password for %s", username)

	// Grant passworded sudo access via a drop-in file
	sudoersPath := filepath.Join("/etc/sudoers.d", username)
	sudoersContent := fmt.Sprintf("%s ALL=(ALL) ALL\n", username)
	if err := os.WriteFile(sudoersPath, []byte(sudoersContent), 0440); err != nil {
		return fmt.Errorf("write sudoers: %w", err)
	}
	log.Printf("[setup] granted sudo to %s", username)

	return nil
}

// runTunnel establishes a WebSocket connection to the backend and bridges it
// bidirectionally with the agent's local SSH server.
//
// Data flow:
//
//	Backend (ssh2 client)
//	  ↕ TCP
//	Backend TCP listener
//	  ↕ WebSocket (binary frames)
//	Agent (this code)
//	  ↕ TCP
//	Agent sshd (127.0.0.1:22)
func runTunnel(backendURL, agentID, sshAddr string) error {
	u, err := url.Parse(backendURL)
	if err != nil {
		return fmt.Errorf("parse backend URL: %w", err)
	}

	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/ws/tunnel/%s", wsScheme, u.Host, agentID)

	log.Printf("[tunnel] dialing WS %s", wsURL)
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}
	defer wsConn.Close()

	log.Printf("[tunnel] WS connected, dialing local SSH %s", sshAddr)
	sshConn, err := dialWithRetry(sshAddr, 10, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer sshConn.Close()

	log.Printf("[tunnel] bridge active (WS <-> SSH)")

	errCh := make(chan error, 2)

	// WS → SSH: data arriving from the backend (SSH client) goes to local sshd
	go func() {
		for {
			_, data, err := wsConn.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("ws read: %w", err)
				return
			}
			if _, err := sshConn.Write(data); err != nil {
				errCh <- fmt.Errorf("ssh write: %w", err)
				return
			}
		}
	}()

	// SSH → WS: data from local sshd goes back to the backend (SSH client)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := sshConn.Read(buf)
			if n > 0 {
				if werr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					errCh <- fmt.Errorf("ws write: %w", werr)
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("ssh read: %w", err)
				}
				return
			}
		}
	}()

	return <-errCh
}

// dialWithRetry attempts to open a TCP connection, retrying up to maxAttempts times.
func dialWithRetry(addr string, maxAttempts int, delay time.Duration) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	for i := 1; i <= maxAttempts; i++ {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		log.Printf("[tunnel] SSH dial attempt %d/%d failed: %v", i, maxAttempts, err)
		time.Sleep(delay)
	}
	return nil, err
}
