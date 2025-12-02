package logging_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lokiPushRequest struct {
	Streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	} `json:"streams"`
}

func TestLokiHandler(t *testing.T) {
	var receivedBody []byte
	var receivedBodyMu sync.Mutex

	// Create a mock Loki server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		receivedBodyMu.Lock()
		receivedBody = body
		receivedBodyMu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	// Create a Loki handler
	labels := map[string]string{"app": "test"}
	handler := logging.NewLokiHandler(server.URL, labels, 1, true, slog.LevelInfo)
	defer handler.Close()

	logger := slog.New(handler)

	// Log a message
	logger.Info("hello, loki", "key", "value")

	// The handler batches logs, so we need to wait for it to flush.
	// Closing the handler will trigger a flush.
	err := handler.Close()
	require.NoError(t, err)

	// Check the received request
	receivedBodyMu.Lock()
	defer receivedBodyMu.Unlock()

	require.NotEmpty(t, receivedBody, "Loki server did not receive any request")

	var pushReq lokiPushRequest
	err = json.Unmarshal(receivedBody, &pushReq)
	require.NoError(t, err)

	require.Len(t, pushReq.Streams, 1)
	stream := pushReq.Streams[0]

	assert.Equal(t, labels, stream.Stream)
	require.Len(t, stream.Values, 1)
	value := stream.Values[0]

	require.Len(t, value, 2)
	// value[0] is the timestamp, which is hard to predict, so we'll just check if it's there.
	assert.NotEmpty(t, value[0])

	// Check the log line
	var logLine map[string]interface{}
	err = json.Unmarshal([]byte(value[1]), &logLine)
	require.NoError(t, err)

	assert.Equal(t, "INFO", logLine["level"])
	assert.Equal(t, "hello, loki", logLine["msg"])
	assert.Equal(t, "value", logLine["key"])
}

func TestLokiHandler_Batching(t *testing.T) {
	var receivedBodies [][]byte
	var receivedBodiesMu sync.Mutex

	// Create a mock Loki server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		receivedBodiesMu.Lock()
		receivedBodies = append(receivedBodies, body)
		receivedBodiesMu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	// Create a Loki handler with a batch size of 2
	handler := logging.NewLokiHandler(server.URL, nil, 2, true, slog.LevelInfo)
	defer handler.Close()

	logger := slog.New(handler)

	// Log one message, should not trigger a flush
	logger.Info("message 1")
	time.Sleep(100 * time.Millisecond) // Give it a moment

	receivedBodiesMu.Lock()
	assert.Empty(t, receivedBodies, "Loki server should not have received any request yet")
	receivedBodiesMu.Unlock()

	// Log a second message, should trigger a flush
	logger.Info("message 2")
	time.Sleep(100 * time.Millisecond) // Give it a moment for the flush to happen

	receivedBodiesMu.Lock()
	assert.Len(t, receivedBodies, 1, "Loki server should have received one request")
	receivedBodiesMu.Unlock()

	// Check the received request
	var pushReq lokiPushRequest
	err := json.Unmarshal(receivedBodies[0], &pushReq)
	require.NoError(t, err)

	require.Len(t, pushReq.Streams, 1)
	stream := pushReq.Streams[0]
	require.Len(t, stream.Values, 2)

	var logLine1, logLine2 map[string]interface{}
	err = json.Unmarshal([]byte(stream.Values[0][1]), &logLine1)
	require.NoError(t, err)
	err = json.Unmarshal([]byte(stream.Values[1][1]), &logLine2)
	require.NoError(t, err)

	assert.Equal(t, "message 1", logLine1["msg"])
	assert.Equal(t, "message 2", logLine2["msg"])
}
