package rldphttp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/xssnick/tonutils-go/adnl/rldp"
)

const asyncTestTimeout = 5 * time.Second

func newAsyncTestServer(t *testing.T, limit int, handler http.Handler) *Server {
	t.Helper()

	srv, err := NewServerWithMaxConcurrentRequests(nil, nil, nil, handler, limit)
	if err != nil {
		t.Fatalf("create test server: %v", err)
	}
	return srv
}

func asyncRequestQuery(requestID []byte) *rldp.Query {
	return &rldp.Query{
		ID:            bytes.Repeat([]byte{0x11}, 32),
		MaxAnswerSize: _RLDPMaxAnswerSize,
		Timeout:       30,
		Data: Request{
			ID:      requestID,
			Method:  http.MethodGet,
			URL:     "/",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Host", Value: "example.ton"}},
		},
	}
}

func asyncGetPartQuery(requestID []byte) *rldp.Query {
	return asyncGetPartQueryAt(requestID, 0)
}

func asyncGetPartQueryAt(requestID []byte, seqno int32) *rldp.Query {
	return &rldp.Query{
		ID:            bytes.Repeat([]byte{0x22}, 32),
		MaxAnswerSize: _RLDPMaxAnswerSize,
		Timeout:       30,
		Data: GetNextPayloadPart{
			ID:           requestID,
			Seqno:        seqno,
			MaxChunkSize: _ChunkSize,
		},
	}
}

func invokeAsyncCallback(
	t *testing.T,
	callback func([]byte, *rldp.Query) error,
	transferID []byte,
	query *rldp.Query,
) error {
	t.Helper()

	result := make(chan error, 1)
	go func() {
		result <- callback(transferID, query)
	}()

	select {
	case err := <-result:
		return err
	case <-time.After(asyncTestTimeout):
		t.Fatal("RLDP callback did not return while its request was still running")
		return nil
	}
}

func waitAsyncSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(asyncTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func dispatcherActive(dispatcher *requestDispatcher) int {
	dispatcher.mx.Lock()
	defer dispatcher.mx.Unlock()
	return dispatcher.active
}

func waitForAsyncCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(asyncTestTimeout)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		<-ticker.C
	}
}

func TestNewServerConcurrentRequestLimit(t *testing.T) {
	defaultServer := NewServer(nil, nil, nil, http.NotFoundHandler())
	if got := defaultServer.dispatcher.limit; got != DefaultMaxConcurrentRequests {
		t.Fatalf("default concurrent request limit = %d, want %d", got, DefaultMaxConcurrentRequests)
	}

	customServer := newAsyncTestServer(t, 7, http.NotFoundHandler())
	if got := customServer.dispatcher.limit; got != 7 {
		t.Fatalf("custom concurrent request limit = %d, want 7", got)
	}

	for _, invalid := range []int{0, -1} {
		if _, err := NewServerWithMaxConcurrentRequests(nil, nil, nil, http.NotFoundHandler(), invalid); err == nil {
			t.Fatalf("expected limit %d to be rejected", invalid)
		}
	}
}

func TestHandleConcurrencyLimitIsGlobalAcrossPeers(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandlers := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer releaseHandlers()

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		<-release
	})
	srv := newAsyncTestServer(t, 2, handler)
	client := &mockRLDP{}

	if err := invokeAsyncCallback(t, srv.handle(client, "peer-1", "127.0.0.1:1001"), []byte("transfer-1"), asyncRequestQuery(bytes.Repeat([]byte{1}, 32))); err != nil {
		t.Fatalf("admit first peer: %v", err)
	}
	if err := invokeAsyncCallback(t, srv.handle(client, "peer-2", "127.0.0.1:1002"), []byte("transfer-2"), asyncRequestQuery(bytes.Repeat([]byte{2}, 32))); err != nil {
		t.Fatalf("admit second peer: %v", err)
	}

	select {
	case <-entered:
	case <-time.After(asyncTestTimeout):
		t.Fatal("first admitted handler did not start")
	}
	select {
	case <-entered:
	case <-time.After(asyncTestTimeout):
		t.Fatal("second admitted handler did not start")
	}

	err := invokeAsyncCallback(t, srv.handle(client, "peer-3", "127.0.0.1:1003"), []byte("transfer-3"), asyncRequestQuery(bytes.Repeat([]byte{3}, 32)))
	if !errors.Is(err, ErrTooManyConcurrentRequests) {
		t.Fatalf("third peer error = %v, want %v", err, ErrTooManyConcurrentRequests)
	}
	if got := dispatcherActive(srv.dispatcher); got != 2 {
		t.Fatalf("active logical requests = %d, want 2", got)
	}
	if got := client.answerCount(); got != 0 {
		t.Fatalf("overload path sent %d answers while admitted handlers were blocked", got)
	}

	releaseHandlers()
	waitForAsyncCondition(t, "both request slots to be released", func() bool {
		return dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleAllowsPayloadContinuationAtFullLimit(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x33}, 32)
	responseReady := make(chan struct{})
	releaseHandler := make(chan struct{})
	var readyOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	defer release()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		readyOnce.Do(func() { close(responseReady) })
		<-releaseHandler
	})
	srv := newAsyncTestServer(t, 1, handler)
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("request-transfer"), asyncRequestQuery(requestID)); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, responseReady, "streaming response registration")
	if got := dispatcherActive(srv.dispatcher); got != 1 {
		t.Fatalf("active logical requests = %d, want 1", got)
	}

	if err := invokeAsyncCallback(t, callback, []byte("part-transfer"), asyncGetPartQuery(requestID)); err != nil {
		t.Fatalf("payload continuation must be admitted at the full request limit: %v", err)
	}
	if got := dispatcherActive(srv.dispatcher); got != 1 {
		t.Fatalf("payload continuation changed logical request count to %d", got)
	}

	release()
	waitForAsyncCondition(t, "first payload continuation", func() bool {
		return client.answerCount() == 2
	})
	if err := invokeAsyncCallback(t, callback, []byte("last-part-transfer"), asyncGetPartQueryAt(requestID, 1)); err != nil {
		t.Fatalf("last payload continuation must be admitted: %v", err)
	}
	waitForAsyncCondition(t, "last payload part and request slot release", func() bool {
		return client.answerCount() == 3 && dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleRejectsUnknownAndConcurrentPayloadContinuations(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x35}, 32)
	responseReady := make(chan struct{})
	releaseHandler := make(chan struct{})
	var readyOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	defer release()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		readyOnce.Do(func() { close(responseReady) })
		<-releaseHandler
	})
	srv := newAsyncTestServer(t, 1, handler)
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("request-transfer"), asyncRequestQuery(requestID)); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, responseReady, "response stream registration")

	unknownID := bytes.Repeat([]byte{0x36}, 32)
	err := invokeAsyncCallback(t, callback, []byte("unknown-part"), asyncGetPartQuery(unknownID))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unknown request id")) {
		t.Fatalf("unknown payload continuation error = %v", err)
	}

	if err := invokeAsyncCallback(t, callback, []byte("part-transfer"), asyncGetPartQuery(requestID)); err != nil {
		t.Fatalf("admit first payload continuation: %v", err)
	}
	stream := srv.activeRequests.get(hex.EncodeToString(requestID))
	if stream == nil || !stream.continuing.Load() {
		t.Fatal("first payload continuation was not marked in flight")
	}

	err = invokeAsyncCallback(t, callback, []byte("duplicate-part"), asyncGetPartQuery(requestID))
	if !errors.Is(err, errPayloadContinuationInProgress) {
		t.Fatalf("concurrent payload continuation error = %v, want %v", err, errPayloadContinuationInProgress)
	}
	if got := dispatcherActive(srv.dispatcher); got != 1 {
		t.Fatalf("continuation attempts changed logical request count to %d", got)
	}

	release()
	waitForAsyncCondition(t, "payload continuation completion", func() bool {
		return client.answerCount() == 2 && dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleReleasesRequestSlotAfterPanic(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer releaseHandler()

	var calls atomic.Int32
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		panic("test panic")
	})
	srv := newAsyncTestServer(t, 1, handler)
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("transfer-1"), asyncRequestQuery(bytes.Repeat([]byte{1}, 32))); err != nil {
		t.Fatalf("admit panicking request: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(asyncTestTimeout):
		t.Fatal("panicking handler did not start")
	}

	err := invokeAsyncCallback(t, callback, []byte("transfer-2"), asyncRequestQuery(bytes.Repeat([]byte{2}, 32)))
	if !errors.Is(err, ErrTooManyConcurrentRequests) {
		t.Fatalf("request while panic handler is active = %v, want limit error", err)
	}

	releaseHandler()
	waitForAsyncCondition(t, "panic recovery to release request slot", func() bool {
		return dispatcherActive(srv.dispatcher) == 0
	})

	if err := invokeAsyncCallback(t, callback, []byte("transfer-3"), asyncRequestQuery(bytes.Repeat([]byte{3}, 32))); err != nil {
		t.Fatalf("request after recovered panic was not admitted: %v", err)
	}
	waitForAsyncCondition(t, "second panic recovery", func() bool {
		return calls.Load() == 2 && dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleCleansResponseStreamAfterHandlerPanic(t *testing.T) {
	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		panic("test panic after response registration")
	}))
	client := &mockRLDP{}

	if err := invokeAsyncCallback(
		t,
		srv.handle(client, "peer", "127.0.0.1:1001"),
		[]byte("transfer"),
		asyncRequestQuery(bytes.Repeat([]byte{0x40}, 32)),
	); err != nil {
		t.Fatalf("admit panicking request: %v", err)
	}
	waitForAsyncCondition(t, "post-registration panic cleanup", func() bool {
		return client.answerCount() == 1 &&
			activeRequestCount(srv) == 0 &&
			dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleReleasesRequestSlotAfterInitialResponseError(t *testing.T) {
	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	client := &mockRLDP{sendErr: errors.New("send failed")}

	err := invokeAsyncCallback(
		t,
		srv.handle(client, "peer", "127.0.0.1:1001"),
		[]byte("transfer"),
		asyncRequestQuery(bytes.Repeat([]byte{0x41}, 32)),
	)
	if err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitForAsyncCondition(t, "failed initial response cleanup", func() bool {
		return client.answerCount() == 1 &&
			activeRequestCount(srv) == 0 &&
			dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandleReleasesRequestSlotAfterPayloadResponseError(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x42}, 32)
	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("request-transfer"), asyncRequestQuery(requestID)); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitForAsyncCondition(t, "initial response stream", func() bool {
		return client.answerCount() == 1 && activeRequestCount(srv) == 1
	})
	client.setSendError(errors.New("send failed"))

	if err := invokeAsyncCallback(t, callback, []byte("part-transfer"), asyncGetPartQuery(requestID)); err != nil {
		t.Fatalf("admit payload continuation: %v", err)
	}
	waitForAsyncCondition(t, "failed payload response cleanup", func() bool {
		return client.answerCount() == 2 &&
			activeRequestCount(srv) == 0 &&
			dispatcherActive(srv.dispatcher) == 0
	})
}

func TestStopRejectsNewQueriesAndRetainsRunningHandlerSlot(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x43}, 32)
	responseReady := make(chan struct{})
	releaseHandler := make(chan struct{})
	var readyOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	defer release()

	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		readyOnce.Do(func() { close(responseReady) })
		<-releaseHandler
	}))
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("request-transfer"), asyncRequestQuery(requestID)); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, responseReady, "streaming response registration")
	if err := srv.Stop(); err != nil {
		t.Fatalf("stop server: %v", err)
	}
	if got := activeRequestCount(srv); got != 0 {
		t.Fatalf("active response streams after Stop = %d, want 0", got)
	}
	if got := dispatcherActive(srv.dispatcher); got != 1 {
		t.Fatalf("running handler slot after Stop = %d, want 1", got)
	}

	if err := invokeAsyncCallback(t, callback, []byte("new-request"), asyncRequestQuery(bytes.Repeat([]byte{0x44}, 32))); !errors.Is(err, ErrServerStopped) {
		t.Fatalf("request after Stop = %v, want %v", err, ErrServerStopped)
	}
	if err := invokeAsyncCallback(t, callback, []byte("new-part"), asyncGetPartQuery(requestID)); !errors.Is(err, ErrServerStopped) {
		t.Fatalf("payload continuation after Stop = %v, want %v", err, ErrServerStopped)
	}

	release()
	waitForAsyncCondition(t, "running handler slot release after Stop", func() bool {
		return dispatcherActive(srv.dispatcher) == 0
	})
}

func TestExpiredResponseReleasesOnlyItsLeaseReference(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x44}, 32)
	responseReady := make(chan struct{})
	releaseHandler := make(chan struct{})
	var readyOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	defer release()

	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		readyOnce.Do(func() { close(responseReady) })
		<-releaseHandler
	}))
	client := &mockRLDP{}

	if err := invokeAsyncCallback(
		t,
		srv.handle(client, "peer", "127.0.0.1:1001"),
		[]byte("request-transfer"),
		asyncRequestQuery(requestID),
	); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, responseReady, "response stream registration")

	expired := srv.activeRequests.expired(time.Now().Add(srv.Timeout + time.Second))
	if len(expired) != 1 {
		t.Fatalf("expired response streams = %d, want 1", len(expired))
	}
	expired[0].finish()
	if got := dispatcherActive(srv.dispatcher); got != 1 {
		t.Fatalf("expiration released the still-running handler slot: active = %d", got)
	}

	release()
	waitForAsyncCondition(t, "handler lease release after response expiry", func() bool {
		return dispatcherActive(srv.dispatcher) == 0
	})
}

func TestHandlerCannotRegisterResponseStreamAfterStop(t *testing.T) {
	entered := make(chan struct{})
	releaseHandler := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	defer release()

	srv := newAsyncTestServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		<-releaseHandler
		_, _ = w.Write([]byte("late payload"))
	}))
	client := &mockRLDP{}
	callback := srv.handle(client, "peer", "127.0.0.1:1001")

	if err := invokeAsyncCallback(t, callback, []byte("request-transfer"), asyncRequestQuery(bytes.Repeat([]byte{0x45}, 32))); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, entered, "handler entry")
	if err := srv.Stop(); err != nil {
		t.Fatalf("stop server: %v", err)
	}

	release()
	waitForAsyncCondition(t, "late handler completion after Stop", func() bool {
		return dispatcherActive(srv.dispatcher) == 0
	})
	if got := activeRequestCount(srv); got != 0 {
		t.Fatalf("late handler registered %d response streams after Stop", got)
	}
	if got := client.answerCount(); got != 0 {
		t.Fatalf("late handler sent %d responses after Stop", got)
	}
}

func TestHandleSnapshotsQueryBeforeReturning(t *testing.T) {
	requestID := bytes.Repeat([]byte{0x44}, 32)
	queryID := bytes.Repeat([]byte{0x55}, 32)
	transferID := bytes.Repeat([]byte{0x66}, 32)
	wantRequestID := bytes.Clone(requestID)
	wantQueryID := bytes.Clone(queryID)
	wantTransferID := bytes.Clone(transferID)

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	releaseHandler := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer releaseHandler()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		_, _ = w.Write([]byte("x"))
	})
	srv := newAsyncTestServer(t, 1, handler)
	client := &mockRLDP{}
	query := asyncRequestQuery(requestID)
	query.ID = queryID

	if err := invokeAsyncCallback(t, srv.handle(client, "peer", "127.0.0.1:1001"), transferID, query); err != nil {
		t.Fatalf("admit request: %v", err)
	}
	waitAsyncSignal(t, entered, "handler entry")

	for i := range requestID {
		requestID[i] ^= 0xff
		queryID[i] ^= 0xff
		transferID[i] ^= 0xff
	}
	releaseHandler()

	waitForAsyncCondition(t, "initial response", func() bool {
		return client.answerCount() == 1
	})
	gotQueryID, gotTransferID := client.answerIDs(t, 0)
	if !bytes.Equal(gotQueryID, wantQueryID) {
		t.Fatalf("answer query ID changed after callback return: %x", gotQueryID)
	}
	if !bytes.Equal(gotTransferID, wantTransferID) {
		t.Fatalf("answer transfer ID changed after callback return: %x", gotTransferID)
	}
	if srv.activeRequests.get(hex.EncodeToString(wantRequestID)) == nil {
		t.Fatal("response stream was registered with mutated request ID")
	}

	callback := srv.handle(client, "peer", "127.0.0.1:1001")
	if err := invokeAsyncCallback(t, callback, []byte("part-transfer"), asyncGetPartQuery(wantRequestID)); err != nil {
		t.Fatalf("fetch snapshotted response stream: %v", err)
	}
	waitForAsyncCondition(t, "snapshotted request completion", func() bool {
		return client.answerCount() == 2 && dispatcherActive(srv.dispatcher) == 0
	})
}

func TestCloneQueryOwnsParseNoCopyFields(t *testing.T) {
	query := asyncRequestQuery(bytes.Repeat([]byte{0x77}, 32))
	original := query.Data.(Request)
	cloned := cloneQuery(query)
	copyRequest := cloned.Data.(Request)

	if unsafe.StringData(original.Method) == unsafe.StringData(copyRequest.Method) ||
		unsafe.StringData(original.URL) == unsafe.StringData(copyRequest.URL) ||
		unsafe.StringData(original.Version) == unsafe.StringData(copyRequest.Version) ||
		unsafe.StringData(original.Headers[0].Name) == unsafe.StringData(copyRequest.Headers[0].Name) ||
		unsafe.StringData(original.Headers[0].Value) == unsafe.StringData(copyRequest.Headers[0].Value) {
		t.Fatal("cloned request retains string storage owned by the TL input buffer")
	}

	query.ID[0] ^= 0xff
	original.ID[0] ^= 0xff
	original.Headers[0] = Header{Name: "Mutated", Value: "mutated"}
	if bytes.Equal(query.ID, cloned.ID) {
		t.Fatal("cloned query ID aliases the source")
	}
	if bytes.Equal(original.ID, copyRequest.ID) {
		t.Fatal("cloned request ID aliases the source")
	}
	if copyRequest.Headers[0].Name != "Host" || copyRequest.Headers[0].Value != "example.ton" {
		t.Fatalf("cloned headers changed with source: %+v", copyRequest.Headers[0])
	}

	partQuery := asyncGetPartQuery(bytes.Repeat([]byte{0x88}, 32))
	partCopy := cloneQuery(partQuery)
	originalPart := partQuery.Data.(GetNextPayloadPart)
	clonedPart := partCopy.Data.(GetNextPayloadPart)
	originalPart.ID[0] ^= 0xff
	if bytes.Equal(originalPart.ID, clonedPart.ID) {
		t.Fatal("cloned payload-part request ID aliases the source")
	}
}

func TestActiveRequestRegistryConditionalDeletePreservesReplacement(t *testing.T) {
	registry := newActiveRequestRegistry()
	key := "request-key"
	first := &payloadStream{Data: newDataStreamer()}
	second := &payloadStream{Data: newDataStreamer()}

	registry.store(key, first)
	if previous := registry.store(key, second); previous != first {
		t.Fatalf("replaced stream = %p, want %p", previous, first)
	}
	if registry.deleteIfSame(key, first) {
		t.Fatal("stale stream deleted its replacement")
	}
	if got := registry.get(key); got != second {
		t.Fatalf("stream after stale delete = %p, want %p", got, second)
	}
	if !registry.deleteIfSame(key, second) {
		t.Fatal("current stream was not deleted")
	}
}
