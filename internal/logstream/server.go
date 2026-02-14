package logstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

const maxBufferedLogs = 1000

// LogEntry represents a single log entry for streaming.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Server provides HTTP log streaming via SSE.
type Server struct {
	logger  *zap.Logger
	apiKey  string
	port    int
	clients map[chan LogEntry]struct{}
	logs    []LogEntry
	mu      sync.RWMutex
	server  *http.Server
}

// NewServer creates a new log streaming server.
func NewServer(port int, apiKey string, logger *zap.Logger) *Server {
	return &Server{
		logger:  logger,
		apiKey:  apiKey,
		port:    port,
		clients: make(map[chan LogEntry]struct{}),
	}
}

// Start starts the log streaming HTTP server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/logs", s.authMiddleware(s.handleLogs))
	mux.HandleFunc("/logs/stream", s.authMiddleware(s.handleStream))
	mux.HandleFunc("/logs/clear", s.authMiddleware(s.handleClear))

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	s.logger.Info("log stream server starting", zap.Int("port", s.port))
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("log stream server error", zap.Error(err))
		}
	}()

	return nil
}

// Stop gracefully stops the server.
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// Broadcast sends a log entry to all connected SSE clients and buffers it.
func (s *Server) Broadcast(entry LogEntry) {
	s.mu.Lock()
	s.logs = append(s.logs, entry)
	if len(s.logs) > maxBufferedLogs {
		s.logs = s.logs[len(s.logs)-maxBufferedLogs:]
	}

	// Copy clients to avoid holding lock during send
	clients := make([]chan LogEntry, 0, len(s.clients))
	for ch := range s.clients {
		clients = append(clients, ch)
	}
	s.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- entry:
		default:
			// Client is slow, skip
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"log-stream"}`))
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	logs := make([]LogEntry, len(s.logs))
	copy(logs, s.logs)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Register client
	ch := make(chan LogEntry, 100)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
		close(ch)
	}()

	ctx := r.Context()
	for {
		select {
		case entry := <-ch:
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	s.logs = nil
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"cleared":true}`))
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			next(w, r)
			return
		}

		key := r.Header.Get("X-Api-Key")
		if key == "" {
			key = r.URL.Query().Get("apiKey")
		}

		if key != s.apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
