package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type limitedWriter struct {
	limit int
	data  bytes.Buffer
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if len(data) > w.limit {
		data = data[:w.limit]
	}
	return w.data.Write(data)
}

func TestWriteFullHandlesShortWrites(t *testing.T) {
	writer := &limitedWriter{limit: 2}
	want := []byte("tunnel data")

	if err := writeFull(writer, want); err != nil {
		t.Fatalf("writeFull returned error: %v", err)
	}
	if got := writer.data.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("writeFull wrote %q, want %q", got, want)
	}
}

func TestWriteFullRejectsWriterWithNoProgress(t *testing.T) {
	if err := writeFull(zeroWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeFull error = %v, want %v", err, io.ErrShortWrite)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestRelaySessionsHaveIndependentFlowControlState(t *testing.T) {
	first := newRelaySession()
	second := newRelaySession()
	if first.writerSemaphore == second.writerSemaphore {
		t.Fatal("relay sessions share a WebSocket writer semaphore")
	}

	first.ackMutex.Lock()
	first.bytesReceived = ackThreshold
	first.lastAckSent = ackThreshold
	first.ackMutex.Unlock()

	second.ackMutex.Lock()
	defer second.ackMutex.Unlock()
	if second.bytesReceived != 0 || second.lastAckSent != 0 {
		t.Fatalf("new relay session inherited ACK state: received=%d sent=%d", second.bytesReceived, second.lastAckSent)
	}
}

func TestExtractDataPayloadValidatesFrameLength(t *testing.T) {
	tunnel := &Tunnel{}
	frame := make([]byte, 9)
	binary.BigEndian.PutUint16(frame[:2], tagData)
	binary.BigEndian.PutUint32(frame[2:6], 3)
	copy(frame[6:], "abc")

	payload, err := tunnel.extractDataPayload(frame)
	if err != nil {
		t.Fatalf("extractDataPayload returned error: %v", err)
	}
	if !bytes.Equal(payload, []byte("abc")) {
		t.Fatalf("payload = %q, want %q", payload, "abc")
	}

	if _, err := tunnel.extractDataPayload(append(frame, 0)); err == nil {
		t.Fatal("extractDataPayload accepted trailing frame data")
	}
	if _, err := tunnel.extractDataPayload(frame[:len(frame)-1]); err == nil {
		t.Fatal("extractDataPayload accepted a truncated payload")
	}
}

func TestPortListenerStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tunnel := &Tunnel{config: Config{LocalHost: "127.0.0.1"}}

	if err := tunnel.startPortMode(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("startPortMode error = %v, want %v", err, context.Canceled)
	}
}
