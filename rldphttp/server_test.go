package rldphttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

type mockRLDP struct {
	mx          sync.Mutex
	answers     []tl.Serializable
	queryIDs    [][]byte
	transferIDs [][]byte
	sendErr     error
}

type blockingReadCloser struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (b *blockingReadCloser) Read([]byte) (int, error) {
	b.enteredOnce.Do(func() {
		close(b.entered)
	})
	<-b.release
	return 0, io.EOF
}

func (b *blockingReadCloser) Close() error {
	b.releaseOnce.Do(func() {
		close(b.release)
	})
	return nil
}

func (m *mockRLDP) Close() {}

func (m *mockRLDP) DoQuery(context.Context, uint64, tl.Serializable, tl.Serializable) error {
	return nil
}

func (m *mockRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}

func (m *mockRLDP) SetOnDisconnect(func()) {}

func (m *mockRLDP) SendAnswer(
	_ context.Context,
	_ uint64,
	_ uint32,
	queryID,
	transferID []byte,
	answer tl.Serializable,
) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	m.answers = append(m.answers, answer)
	m.queryIDs = append(m.queryIDs, bytes.Clone(queryID))
	m.transferIDs = append(m.transferIDs, bytes.Clone(transferID))
	return m.sendErr
}

func (m *mockRLDP) response(t *testing.T, i int) Response {
	t.Helper()

	m.mx.Lock()
	defer m.mx.Unlock()

	if len(m.answers) <= i {
		t.Fatalf("expected answer %d, got %d answers", i, len(m.answers))
	}

	resp, ok := m.answers[i].(Response)
	if !ok {
		t.Fatalf("expected Response, got %T", m.answers[i])
	}
	return resp
}

func (m *mockRLDP) answerCount() int {
	m.mx.Lock()
	defer m.mx.Unlock()

	return len(m.answers)
}

func (m *mockRLDP) setSendError(err error) {
	m.mx.Lock()
	m.sendErr = err
	m.mx.Unlock()
}

func (m *mockRLDP) answerIDs(t *testing.T, i int) ([]byte, []byte) {
	t.Helper()

	m.mx.Lock()
	defer m.mx.Unlock()

	if len(m.answers) <= i {
		t.Fatalf("expected answer %d, got %d answers", i, len(m.answers))
	}
	return bytes.Clone(m.queryIDs[i]), bytes.Clone(m.transferIDs[i])
}

func newTestRespWriter(sendErr error) (*respWriter, *writerBuff, *mockRLDP) {
	rl := &mockRLDP{sendErr: sendErr}
	srv := &Server{
		activeRequests: newActiveRequestRegistry(),
		Timeout:        time.Minute,
	}
	wb := &writerBuff{
		client:      rl,
		server:      srv,
		stream:      newDataStreamer(),
		maxAnswerSz: _RLDPMaxAnswerSize,
		timeout:     30,
		queryId:     []byte("query-id-query-id-query-id-12"),
		requestId:   []byte("request-id-request-id-request-1"),
		transferId:  []byte("transfer-id"),
	}
	rw := &respWriter{
		writer:  bufio.NewWriterSize(wb, _ChunkSize),
		wb:      wb,
		headers: http.Header{},
	}
	wb.resp = rw
	return rw, wb, rl
}

func finishWriter(rw *respWriter, wb *writerBuff) error {
	wb.handled = true
	if rw.err != nil {
		return rw.err
	}
	if err := rw.writer.Flush(); err != nil {
		return err
	}
	if err := wb.flush(nil, false); err != nil {
		return err
	}
	wb.stream.Finish()
	return nil
}

func responseHeader(resp Response, name string) string {
	name = http.CanonicalHeaderKey(name)
	for _, hdr := range resp.Headers {
		if http.CanonicalHeaderKey(hdr.Name) == name {
			return hdr.Value
		}
	}
	return ""
}

func activeStream(t *testing.T, srv *Server, requestID []byte) *payloadStream {
	t.Helper()

	stream := srv.activeRequests.get(hex.EncodeToString(requestID))
	if stream == nil {
		t.Fatal("expected active request stream")
	}
	return stream
}

func activeRequestCount(srv *Server) int {
	return srv.activeRequests.len()
}

func testRemoteAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}

func readPayloadPart(t *testing.T, wb *writerBuff, seqno int32) *PayloadPart {
	t.Helper()

	stream := activeStream(t, wb.server, wb.requestId)

	part, err := handleGetPart(GetNextPayloadPart{
		ID:           wb.requestId,
		Seqno:        seqno,
		MaxChunkSize: _ChunkSize,
	}, stream)
	if err != nil {
		t.Fatalf("handle get part: %v", err)
	}
	return part
}

func readPayloadPartWithin(t *testing.T, wb *writerBuff, seqno int32, timeout time.Duration) *PayloadPart {
	t.Helper()

	stream := activeStream(t, wb.server, wb.requestId)

	type result struct {
		part *PayloadPart
		err  error
	}
	done := make(chan result, 1)
	go func() {
		part, err := handleGetPart(GetNextPayloadPart{
			ID:           wb.requestId,
			Seqno:        seqno,
			MaxChunkSize: _ChunkSize,
		}, stream)
		done <- result{part: part, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("handle get part: %v", res.err)
		}
		return res.part
	case <-time.After(timeout):
		_ = stream.Data.Close()
		t.Fatalf("timed out waiting for payload part %d", seqno)
		return nil
	}
}

func TestParseRequestHeadersAllowsMatchingContentLength(t *testing.T) {
	headers, host, contentLen, err := parseRequestHeaders([]Header{
		{Name: "Host", Value: "example.ton"},
		{Name: "Content-Length", Value: "7"},
		{Name: "content-length", Value: " 7 "},
	})
	if err != nil {
		t.Fatalf("parse request headers: %v", err)
	}
	if host != "example.ton" {
		t.Fatalf("unexpected host: %q", host)
	}
	if contentLen != 7 {
		t.Fatalf("unexpected content length: %d", contentLen)
	}
	if got := headers.Values("Content-Length"); len(got) != 2 {
		t.Fatalf("expected both Content-Length values to be preserved, got %q", got)
	}
}

func TestHandleRequestRejectsInvalidHeadersWithBadRequest(t *testing.T) {
	tooManyHeaders := make([]Header, maxHTTPHeaderCount+1)
	for i := range tooManyHeaders {
		tooManyHeaders[i] = Header{Name: "X-Test", Value: "value"}
	}

	tests := []struct {
		name    string
		headers []Header
	}{
		{
			name:    "too many headers",
			headers: tooManyHeaders,
		},
		{
			name: "bad header name",
			headers: []Header{
				{Name: "Bad Name", Value: "value"},
			},
		},
		{
			name: "header value injection",
			headers: []Header{
				{Name: "X-Test", Value: "ok\r\nInjected: yes"},
			},
		},
		{
			name: "duplicate host",
			headers: []Header{
				{Name: "Host", Value: "first.ton"},
				{Name: "host", Value: "second.ton"},
			},
		},
		{
			name: "content length and transfer encoding",
			headers: []Header{
				{Name: "Content-Length", Value: "0"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
		},
		{
			name: "conflicting content length",
			headers: []Header{
				{Name: "Content-Length", Value: "1"},
				{Name: "Content-Length", Value: "2"},
			},
		},
		{
			name: "bad content length",
			headers: []Header{
				{Name: "Content-Length", Value: "abc"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{
				activeRequests: newActiveRequestRegistry(),
				Timeout:        time.Minute,
				handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("handler should not be called")
				}),
			}
			rl := &mockRLDP{}

			err := srv.handleQuery(nil, nil, rl, "adnl-id", testRemoteAddr(), []byte("transfer"), &rldp.Query{
				ID:            []byte("query-id-query-id-query-id-12"),
				MaxAnswerSize: _RLDPMaxAnswerSize,
				Timeout:       30,
				Data: Request{
					ID:      []byte("request-id-request-id-request-1"),
					Method:  http.MethodGet,
					URL:     "/",
					Version: "HTTP/1.1",
					Headers: tt.headers,
				},
			})
			if err != nil {
				t.Fatalf("handle request: %v", err)
			}

			if got := rl.answerCount(); got != 1 {
				t.Fatalf("expected one response, got %d", got)
			}
			resp := rl.response(t, 0)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("unexpected status: %d", resp.StatusCode)
			}
			if !resp.NoPayload {
				t.Fatal("expected no payload")
			}
			if got := activeRequestCount(srv); got != 0 {
				t.Fatalf("expected no active request streams, got %d", got)
			}
		})
	}
}

func TestWriterFinalResponseSetsContentLengthAndPayload(t *testing.T) {
	rw, wb, rl := newTestRespWriter(nil)
	rw.Header().Set("X-Test", "ok")

	if _, err := rw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := finishWriter(rw, wb); err != nil {
		t.Fatalf("finish: %v", err)
	}

	resp := rl.response(t, 0)
	if resp.NoPayload {
		t.Fatal("expected response payload")
	}
	if got := responseHeader(resp, "Content-Length"); got != "5" {
		t.Fatalf("unexpected content length: %q", got)
	}
	if got := responseHeader(resp, "Transfer-Encoding"); got != "" {
		t.Fatalf("unexpected transfer encoding: %q", got)
	}
	if got := responseHeader(resp, "X-Test"); got != "ok" {
		t.Fatalf("missing custom header: %q", got)
	}

	part := readPayloadPart(t, wb, 0)
	if string(part.Data) != "hello" {
		t.Fatalf("unexpected payload: %q", string(part.Data))
	}
	if !part.IsLast {
		t.Fatal("expected last payload part")
	}
}

func TestWriterEmptyResponseHasNoPayload(t *testing.T) {
	rw, wb, rl := newTestRespWriter(nil)

	if err := finishWriter(rw, wb); err != nil {
		t.Fatalf("finish: %v", err)
	}

	resp := rl.response(t, 0)
	if !resp.NoPayload {
		t.Fatal("expected no payload")
	}
	if got := responseHeader(resp, "Content-Length"); got != "0" {
		t.Fatalf("unexpected content length: %q", got)
	}
	if got := activeRequestCount(wb.server); got != 0 {
		t.Fatalf("expected no active streams, got %d", got)
	}
}

func TestWriterPreservesExplicitStatus(t *testing.T) {
	rw, wb, rl := newTestRespWriter(nil)

	rw.WriteHeader(http.StatusCreated)
	if _, err := rw.Write([]byte("created")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := finishWriter(rw, wb); err != nil {
		t.Fatalf("finish: %v", err)
	}

	resp := rl.response(t, 0)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if resp.Reason != http.StatusText(http.StatusCreated) {
		t.Fatalf("unexpected reason: %q", resp.Reason)
	}
}

func TestWriterFlushStreamsBufferedBodyAsChunked(t *testing.T) {
	rw, wb, rl := newTestRespWriter(nil)
	if _, ok := interface{}(rw).(http.Flusher); !ok {
		t.Fatal("respWriter should implement http.Flusher")
	}

	rw.Header().Set("Content-Type", "text/event-stream")
	if _, err := rw.Write([]byte("first")); err != nil {
		t.Fatalf("write first: %v", err)
	}
	rw.Flush()
	if rw.err != nil {
		t.Fatalf("flush: %v", rw.err)
	}

	resp := rl.response(t, 0)
	if resp.NoPayload {
		t.Fatal("expected streamed payload")
	}
	if got := responseHeader(resp, "Transfer-Encoding"); got != "chunked" {
		t.Fatalf("unexpected transfer encoding: %q", got)
	}
	if got := responseHeader(resp, "Content-Length"); got != "" {
		t.Fatalf("unexpected content length: %q", got)
	}

	part := readPayloadPartWithin(t, wb, 0, time.Second)
	if string(part.Data) != "first" {
		t.Fatalf("unexpected flushed payload: %q", string(part.Data))
	}
	if part.IsLast {
		t.Fatal("did not expect flushed payload to be last")
	}

	if _, err := rw.Write([]byte("second")); err != nil {
		t.Fatalf("write second: %v", err)
	}
	if err := finishWriter(rw, wb); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if got := rl.answerCount(); got != 1 {
		t.Fatalf("expected one response, got %d", got)
	}

	part = readPayloadPart(t, wb, 1)
	if string(part.Data) != "second" {
		t.Fatalf("unexpected payload: %q", string(part.Data))
	}
	if !part.IsLast {
		t.Fatal("expected last payload part")
	}
}

func TestWriterFlushHeadersBeforeBodyKeepsPayloadOpen(t *testing.T) {
	rw, wb, rl := newTestRespWriter(nil)
	rw.Header().Set("Content-Type", "text/event-stream")

	rw.Flush()
	if rw.err != nil {
		t.Fatalf("flush: %v", rw.err)
	}

	resp := rl.response(t, 0)
	if resp.NoPayload {
		t.Fatal("expected payload stream to stay open after header-only flush")
	}
	if got := responseHeader(resp, "Transfer-Encoding"); got != "chunked" {
		t.Fatalf("unexpected transfer encoding: %q", got)
	}

	if _, err := rw.Write([]byte("later")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := finishWriter(rw, wb); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if got := rl.answerCount(); got != 1 {
		t.Fatalf("expected one response, got %d", got)
	}

	part := readPayloadPart(t, wb, 0)
	if string(part.Data) != "later" {
		t.Fatalf("unexpected payload: %q", string(part.Data))
	}
}

func TestWriterFlushPropagatesSendAnswerError(t *testing.T) {
	sendErr := errors.New("send failed")
	rw, wb, _ := newTestRespWriter(sendErr)

	if _, err := rw.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	wb.handled = true
	err := rw.writer.Flush()
	if !errors.Is(err, sendErr) {
		t.Fatalf("expected send error, got %v", err)
	}
	if got := activeRequestCount(wb.server); got != 0 {
		t.Fatalf("expected active request cleanup after send error, got %d", got)
	}
}

func TestWriterFlushStoresSendAnswerError(t *testing.T) {
	sendErr := errors.New("send failed")
	rw, _, _ := newTestRespWriter(sendErr)

	rw.Flush()
	if !errors.Is(rw.err, sendErr) {
		t.Fatalf("expected flush error, got %v", rw.err)
	}
}

func TestHandleGetPartRejectsInvalidRequestBounds(t *testing.T) {
	tests := []struct {
		name string
		req  GetNextPayloadPart
	}{
		{
			name: "negative seqno",
			req:  GetNextPayloadPart{Seqno: -1, MaxChunkSize: 1},
		},
		{
			name: "zero chunk",
			req:  GetNextPayloadPart{Seqno: 0, MaxChunkSize: 0},
		},
		{
			name: "negative chunk",
			req:  GetNextPayloadPart{Seqno: 0, MaxChunkSize: -1},
		},
		{
			name: "large offset mismatch without overflow",
			req:  GetNextPayloadPart{Seqno: 1 << 30, MaxChunkSize: _ChunkSize},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := &payloadStream{
				Data: io.NopCloser(strings.NewReader("abc")),
			}
			_, err := handleGetPart(tt.req, stream)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHandleGetPartClampsOversizedRequest(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), _ChunkSize+7)
	data := newDataStreamer()
	if _, err := data.Write(payload); err != nil {
		t.Fatalf("write test stream: %v", err)
	}
	data.Finish()

	stream := &payloadStream{
		Data: data,
	}

	part, err := handleGetPart(GetNextPayloadPart{
		ID:           []byte("id"),
		Seqno:        0,
		MaxChunkSize: _ChunkSize + 1,
	}, stream)
	if err != nil {
		t.Fatalf("handle get part: %v", err)
	}
	if len(part.Data) != _ChunkSize {
		t.Fatalf("unexpected payload size: %d", len(part.Data))
	}
	if part.IsLast {
		t.Fatal("did not expect last part")
	}
}

func TestHandleGetPartAcceptsValidRequest(t *testing.T) {
	data := newDataStreamer()
	if _, err := data.Write([]byte("abc")); err != nil {
		t.Fatalf("write test stream: %v", err)
	}
	data.Finish()

	stream := &payloadStream{
		Data: data,
	}

	part, err := handleGetPart(GetNextPayloadPart{
		ID:           []byte("id"),
		Seqno:        0,
		MaxChunkSize: 2,
	}, stream)
	if err != nil {
		t.Fatalf("handle get part: %v", err)
	}
	if string(part.Data) != "ab" {
		t.Fatalf("unexpected payload: %q", string(part.Data))
	}
	if part.IsLast {
		t.Fatal("did not expect last part")
	}

	part, err = handleGetPart(GetNextPayloadPart{
		ID:           []byte("id"),
		Seqno:        1,
		MaxChunkSize: 2,
	}, stream)
	if err != nil {
		t.Fatalf("handle get second part: %v", err)
	}
	if string(part.Data) != "c" {
		t.Fatalf("unexpected second payload: %q", string(part.Data))
	}
	if !part.IsLast {
		t.Fatal("expected last part")
	}
}

func TestHandleGetPartDoesNotHoldSeqnoLockWhileReading(t *testing.T) {
	reader := &blockingReadCloser{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	stream := &payloadStream{
		Data: reader,
	}

	done := make(chan error, 1)
	go func() {
		_, err := handleGetPart(GetNextPayloadPart{
			ID:           []byte("id"),
			Seqno:        0,
			MaxChunkSize: _ChunkSize,
		}, stream)
		done <- err
	}()

	select {
	case <-reader.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for read to start")
	}

	lockAcquired := make(chan struct{})
	go func() {
		stream.mx.Lock()
		stream.mx.Unlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
	case <-time.After(time.Second):
		_ = reader.Close()
		t.Fatal("stream seqno lock is held while payload read is blocked")
	}

	_ = reader.Close()
	if err := <-done; err != nil {
		t.Fatalf("handle get part: %v", err)
	}
}

func TestDataStreamerSplitsLargeWritesIntoChunkSizedReads(t *testing.T) {
	payload := make([]byte, _ChunkSize+7)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	stream := newDataStreamer()
	n, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected written bytes: %d", n)
	}
	stream.Finish()

	first := make([]byte, _ChunkSize)
	n, err = stream.Read(first)
	if err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	if n != _ChunkSize {
		t.Fatalf("unexpected first chunk size: %d", n)
	}
	if !bytes.Equal(first, payload[:_ChunkSize]) {
		t.Fatal("first chunk data mismatch")
	}

	second := make([]byte, _ChunkSize)
	n, err = stream.Read(second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after tail chunk, got %v", err)
	}
	if n != 7 {
		t.Fatalf("unexpected tail chunk size: %d", n)
	}
	if !bytes.Equal(second[:n], payload[_ChunkSize:]) {
		t.Fatal("tail chunk data mismatch")
	}
}

func TestHandleGetPartRefreshesActiveRequestTTL(t *testing.T) {
	data := newDataStreamer()
	if _, err := data.Write([]byte("x")); err != nil {
		t.Fatalf("write test stream: %v", err)
	}
	if err := data.FlushReader(); err != nil {
		t.Fatalf("flush test stream: %v", err)
	}

	requestID := []byte("request-id-request-id-request-1")
	requestKey := hex.EncodeToString(requestID)
	oldTTL := time.Now().Add(-time.Second)
	srv := &Server{
		activeRequests: newActiveRequestRegistry(),
		Timeout:        time.Minute,
	}
	srv.activeRequests.store(requestKey, &payloadStream{
		Data:      data,
		ValidTill: oldTTL,
	})
	rl := &mockRLDP{}

	err := srv.handleQuery(nil, nil, rl, "adnl-id", testRemoteAddr(), []byte("transfer"), &rldp.Query{
		ID:            []byte("query-id-query-id-query-id-12"),
		MaxAnswerSize: _RLDPMaxAnswerSize,
		Timeout:       30,
		Data: GetNextPayloadPart{
			ID:           requestID,
			Seqno:        0,
			MaxChunkSize: _ChunkSize,
		},
	})
	if err != nil {
		t.Fatalf("handle get payload: %v", err)
	}

	stream := srv.activeRequests.get(requestKey)
	if stream == nil {
		t.Fatal("expected stream to stay active")
	}
	if !stream.ValidTill.After(oldTTL) {
		t.Fatalf("expected ttl refresh, got %v <= %v", stream.ValidTill, oldTTL)
	}
}

func TestHandleGetPartSendAnswerErrorCleansActiveRequest(t *testing.T) {
	data := newDataStreamer()
	if _, err := data.Write([]byte("x")); err != nil {
		t.Fatalf("write test stream: %v", err)
	}
	if err := data.FlushReader(); err != nil {
		t.Fatalf("flush test stream: %v", err)
	}

	requestID := []byte("request-id-request-id-request-1")
	requestKey := hex.EncodeToString(requestID)
	srv := &Server{
		activeRequests: newActiveRequestRegistry(),
		Timeout:        time.Minute,
	}
	srv.activeRequests.store(requestKey, &payloadStream{
		Data:      data,
		ValidTill: time.Now().Add(time.Minute),
	})

	sendErr := errors.New("send failed")
	rl := &mockRLDP{sendErr: sendErr}
	err := srv.handleQuery(nil, nil, rl, "adnl-id", testRemoteAddr(), []byte("transfer"), &rldp.Query{
		ID:            []byte("query-id-query-id-query-id-12"),
		MaxAnswerSize: _RLDPMaxAnswerSize,
		Timeout:       30,
		Data: GetNextPayloadPart{
			ID:           requestID,
			Seqno:        0,
			MaxChunkSize: _ChunkSize,
		},
	})
	if !errors.Is(err, sendErr) {
		t.Fatalf("expected send error, got %v", err)
	}
	if got := activeRequestCount(srv); got != 0 {
		t.Fatalf("expected active request cleanup after payload send error, got %d", got)
	}
}

var _ RLDP = (*mockRLDP)(nil)
var _ http.Flusher = (*respWriter)(nil)
