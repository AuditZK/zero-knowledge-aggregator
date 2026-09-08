package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newMuteCTraderWSServer upgrades the connection and then answers nothing —
// the half-open socket cTrader leaves behind when the peer disappears.
func newMuteCTraderWSServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Hold the socket open, read and discard, reply to nothing. Ping
		// frames are answered automatically by gorilla's default handler, so
		// this reproduces the worst case: TCP fine, application dead.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// E-H2: a request that times out must invalidate the socket. Before the fix
// c.ws stayed non-nil, so every later call on the cached instance paid the
// full timeout again for the rest of the one-hour cache TTL.
func TestCTraderRequestTimeout_InvalidatesSocket(t *testing.T) {
	server := newMuteCTraderWSServer(t)

	c := &CTrader{
		clientID:       "client-id",
		clientSecret:   "client-secret",
		accessToken:    "token",
		isLive:         true,
		wsLiveURL:      toWSURL(server.URL),
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		requestTimeout: 150 * time.Millisecond,
	}

	_, err := c.sendMessage(context.Background(), ctraderPayloadAppAuthReq, map[string]any{}, ctraderPayloadAppAuthRes)
	if err == nil {
		t.Fatal("expected a timeout error from a mute server")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("unexpected error: %v", err)
	}

	c.connMu.Lock()
	ws := c.ws
	authed := c.appAuthenticated
	c.connMu.Unlock()
	if ws != nil {
		t.Fatal("socket still installed after a request timeout — the next call would time out again on the same dead socket")
	}
	if authed {
		t.Fatal("appAuthenticated survived the teardown")
	}
}

// A socket that produces nothing at all must eventually fail its read, which
// is the only signal a half-open connection ever gives.
func TestCTraderReadDeadline_TearsDownSilentSocket(t *testing.T) {
	server := newMuteCTraderWSServer(t)

	c := &CTrader{
		clientID:     "client-id",
		clientSecret: "client-secret",
		accessToken:  "token",
		isLive:       true,
		wsLiveURL:    toWSURL(server.URL),
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		readDeadline: 120 * time.Millisecond,
	}

	if err := c.ensureConnected(context.Background()); err != nil {
		t.Fatalf("ensureConnected: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		c.connMu.Lock()
		ws := c.ws
		c.connMu.Unlock()
		if ws == nil {
			return // read deadline fired, socket torn down
		}
		if time.Now().After(deadline) {
			t.Fatal("silent socket still marked connected after the read deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
