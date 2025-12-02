package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// LokiHandler is a custom slog.Handler that sends logs directly to Loki via HTTP.
// It batches logs and sends them asynchronously to avoid blocking the application.
type LokiHandler struct {
	url        string
	labels     map[string]string
	client     *http.Client
	batch      []lokiEntry
	batchMu    sync.Mutex
	batchSize  int
	flushTimer *time.Timer
	enabled    bool
	level      slog.Level
}

type lokiEntry struct {
	timestamp time.Time
	line      string
}

type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// NewLokiHandler creates a new handler that sends logs to Loki.
// url: Loki endpoint (e.g., "http://localhost:3100")
// labels: Static labels to attach to all logs (e.g., {"app": "go-authstarter"})
// batchSize: Number of logs to batch before sending (0 = send immediately)
func NewLokiHandler(url string, labels map[string]string, batchSize int, enabled bool, level slog.Level) *LokiHandler {
	if labels == nil {
		labels = make(map[string]string)
	}

	h := &LokiHandler{
		url:       url + "/loki/api/v1/push",
		labels:    labels,
		client:    &http.Client{Timeout: 5 * time.Second},
		batch:     make([]lokiEntry, 0, batchSize),
		batchSize: batchSize,
		enabled:   enabled,
		level:     level,
	}

	// Start periodic flush (every 5 seconds)
	if batchSize > 0 && enabled {
		h.flushTimer = time.AfterFunc(5*time.Second, h.periodicFlush)
	}

	return h
}

// Enabled reports whether the handler handles records at the given level.
func (h *LokiHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.enabled && level >= h.level
}

// Handle handles the Record.
func (h *LokiHandler) Handle(_ context.Context, r slog.Record) error {
	if !h.enabled {
		return nil
	}

	// Convert slog.Record to JSON string
	logData := map[string]interface{}{
		"time":  r.Time.Format(time.RFC3339Nano),
		"level": r.Level.String(),
		"msg":   r.Message,
	}

	// Add all attributes
	r.Attrs(func(a slog.Attr) bool {
		logData[a.Key] = a.Value.Any()
		return true
	})

	logJSON, err := json.Marshal(logData)
	if err != nil {
		return fmt.Errorf("failed to marshal log to JSON: %w", err)
	}

	entry := lokiEntry{
		timestamp: r.Time,
		line:      string(logJSON),
	}

	// Add to batch
	h.batchMu.Lock()
	h.batch = append(h.batch, entry)
	shouldFlush := len(h.batch) >= h.batchSize && h.batchSize > 0
	h.batchMu.Unlock()

	// Flush if batch is full
	if shouldFlush {
		return h.flush()
	}

	// If batchSize is 0, send immediately
	if h.batchSize == 0 {
		return h.flush()
	}

	return nil
}

// WithAttrs returns a new Handler whose attributes consist of
// both the receiver's attributes and the arguments.
func (h *LokiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For simplicity, we don't support persistent attributes in this handler
	// You could extend this to store attrs and add them to all logs
	return h
}

// WithGroup returns a new Handler with the given group appended to
// the receiver's existing groups.
func (h *LokiHandler) WithGroup(name string) slog.Handler {
	// For simplicity, we don't support groups in this handler
	return h
}

// flush sends all batched logs to Loki
func (h *LokiHandler) flush() error {
	h.batchMu.Lock()
	if len(h.batch) == 0 {
		h.batchMu.Unlock()
		return nil
	}

	// Copy batch and clear
	entries := make([]lokiEntry, len(h.batch))
	copy(entries, h.batch)
	h.batch = h.batch[:0]
	h.batchMu.Unlock()

	// Convert to Loki format
	values := make([][]string, len(entries))
	for i, entry := range entries {
		// Loki expects [timestamp_in_nanoseconds, log_line]
		values[i] = []string{
			fmt.Sprintf("%d", entry.timestamp.UnixNano()),
			entry.line,
		}
	}

	pushReq := lokiPushRequest{
		Streams: []lokiStream{
			{
				Stream: h.labels,
				Values: values,
			},
		},
	}

	// Send to Loki
	return h.sendToLoki(pushReq)
}

// sendToLoki sends the push request to Loki via HTTP
func (h *LokiHandler) sendToLoki(req lokiPushRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal push request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", h.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		// Don't fail the application if Loki is down
		// Just log to stderr
		fmt.Fprintf(io.Discard, "Failed to send logs to Loki: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(io.Discard, "Loki returned error %d: %s\n", resp.StatusCode, string(body))
		return nil
	}

	return nil
}

// periodicFlush is called by the timer to flush logs periodically
func (h *LokiHandler) periodicFlush() {
	_ = h.flush()
	// Reset timer for next flush
	if h.flushTimer != nil {
		h.flushTimer.Reset(5 * time.Second)
	}
}

// Close flushes any remaining logs and stops the periodic flush timer
func (h *LokiHandler) Close() error {
	if h.flushTimer != nil {
		h.flushTimer.Stop()
	}
	return h.flush()
}
