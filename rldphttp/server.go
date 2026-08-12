package rldphttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl"
	adnladdress "github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	dht DHT

	key            ed25519.PrivateKey
	handler        http.Handler
	rldpInfos      map[string]*rldpInfo
	activeRequests *activeRequestRegistry
	adnlServer     *adnl.Gateway
	externalIp     net.IP
	dispatcher     *requestDispatcher

	closer chan bool
	closed bool
	mx     sync.RWMutex

	Timeout time.Duration
}

type writerBuff struct {
	client RLDP

	server *Server
	stream *dataStreamer

	resp *respWriter

	headerSent bool
	handled    bool

	maxAnswerSz uint64
	timeout     uint32
	queryId     []byte
	requestId   []byte
	transferId  []byte
	lease       *requestLease
	registered  *payloadStream

	flushReaderPendingBytes int64
	mx                      sync.Mutex
}

const (
	// DefaultMaxConcurrentRequests is the server-wide admission limit used by NewServer.
	DefaultMaxConcurrentRequests = 20_000
	activeRequestShardCount      = 64
	maxHTTPHeaderCount           = 256
)

var (
	// ErrTooManyConcurrentRequests is returned without blocking when the server-wide limit is full.
	ErrTooManyConcurrentRequests = errors.New("too many concurrent RLDP HTTP requests")
	// ErrServerStopped is returned when a query arrives after Server.Stop.
	ErrServerStopped                 = errors.New("RLDP HTTP server is stopped")
	errPayloadContinuationInProgress = errors.New("RLDP HTTP payload continuation is already in progress")
)

type requestDispatcher struct {
	mx      sync.Mutex
	active  int
	limit   int
	stopped bool
}

type requestLease struct {
	dispatcher *requestDispatcher
	mx         sync.Mutex
	references int
}

func newRequestDispatcher(limit int) *requestDispatcher {
	return &requestDispatcher{limit: limit}
}

func (d *requestDispatcher) acquire() error {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.stopped {
		return ErrServerStopped
	}
	if d.active >= d.limit {
		return ErrTooManyConcurrentRequests
	}
	d.active++
	return nil
}

func (d *requestDispatcher) checkRunning() error {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.stopped {
		return ErrServerStopped
	}
	return nil
}

func (d *requestDispatcher) release() {
	d.mx.Lock()
	d.active--
	d.mx.Unlock()
}

func (d *requestDispatcher) stop() {
	d.mx.Lock()
	d.stopped = true
	d.mx.Unlock()
}

func newRequestLease(dispatcher *requestDispatcher) *requestLease {
	return &requestLease{
		dispatcher: dispatcher,
		references: 1,
	}
}

func (l *requestLease) retainForResponse() {
	l.mx.Lock()
	l.references++
	l.mx.Unlock()
}

func (l *requestLease) release() {
	l.mx.Lock()
	l.references--
	releaseDispatcher := l.references == 0
	l.mx.Unlock()

	if releaseDispatcher {
		l.dispatcher.release()
	}
}

type activeRequestRegistry struct {
	shards [activeRequestShardCount]activeRequestShard
}

type activeRequestShard struct {
	mx      sync.RWMutex
	streams map[string]*payloadStream
}

type respWriter struct {
	writer     *bufio.Writer
	wb         *writerBuff
	statusCode int
	headers    http.Header
	err        error
}

var Logger = log.Println

func newActiveRequestRegistry() *activeRequestRegistry {
	registry := &activeRequestRegistry{}
	for i := range registry.shards {
		registry.shards[i].streams = map[string]*payloadStream{}
	}
	return registry
}

func (r *activeRequestRegistry) shard(key string) *activeRequestShard {
	var hash uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return &r.shards[hash%activeRequestShardCount]
}

func (r *activeRequestRegistry) store(key string, stream *payloadStream) *payloadStream {
	shard := r.shard(key)
	shard.mx.Lock()
	previous := shard.streams[key]
	shard.streams[key] = stream
	shard.mx.Unlock()
	return previous
}

func (r *activeRequestRegistry) getAndRefresh(key string, validTill time.Time) *payloadStream {
	shard := r.shard(key)
	shard.mx.Lock()
	stream := shard.streams[key]
	if stream != nil {
		stream.ValidTill = validTill
	}
	shard.mx.Unlock()
	return stream
}

func (r *activeRequestRegistry) claimContinuation(
	key string,
	validTill time.Time,
) (stream *payloadStream, exists bool) {
	shard := r.shard(key)
	shard.mx.Lock()
	defer shard.mx.Unlock()

	stream = shard.streams[key]
	if stream == nil {
		return nil, false
	}
	if !stream.tryStartContinuation() {
		return nil, true
	}
	stream.ValidTill = validTill
	return stream, true
}

func (r *activeRequestRegistry) get(key string) *payloadStream {
	shard := r.shard(key)
	shard.mx.RLock()
	stream := shard.streams[key]
	shard.mx.RUnlock()
	return stream
}

func (r *activeRequestRegistry) deleteIfSame(key string, expected *payloadStream) bool {
	shard := r.shard(key)
	shard.mx.Lock()
	defer shard.mx.Unlock()

	if shard.streams[key] != expected {
		return false
	}
	delete(shard.streams, key)
	return true
}

func (r *activeRequestRegistry) expired(now time.Time) []*payloadStream {
	var expired []*payloadStream
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mx.Lock()
		for key, stream := range shard.streams {
			if stream.ValidTill.Before(now) {
				delete(shard.streams, key)
				expired = append(expired, stream)
			}
		}
		shard.mx.Unlock()
	}
	return expired
}

func (r *activeRequestRegistry) drain() []*payloadStream {
	var streams []*payloadStream
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mx.Lock()
		for key, stream := range shard.streams {
			delete(shard.streams, key)
			streams = append(streams, stream)
		}
		shard.mx.Unlock()
	}
	return streams
}

func (r *activeRequestRegistry) len() int {
	total := 0
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mx.RLock()
		total += len(shard.streams)
		shard.mx.RUnlock()
	}
	return total
}

func validateHTTPHeader(header Header) error {
	if header.Name == "" {
		return fmt.Errorf("empty header name")
	}
	for _, c := range header.Name {
		switch c {
		case ' ', '\t', '\r', '\n', ':':
			return fmt.Errorf("bad character in header name %q", header.Name)
		}
	}
	if strings.ContainsAny(header.Value, "\r\n") {
		return fmt.Errorf("bad character in header value for %q", header.Name)
	}
	return nil
}

func parseRequestHeaders(reqHeaders []Header) (http.Header, string, int64, error) {
	if len(reqHeaders) > maxHTTPHeaderCount {
		return nil, "", -1, fmt.Errorf("too many headers: %d > %d", len(reqHeaders), maxHTTPHeaderCount)
	}

	contentLen := int64(-1)
	hasContentLength := false
	hasTransferEncoding := false
	hasHost := false
	host := ""
	headers := http.Header{}

	for _, header := range reqHeaders {
		if err := validateHTTPHeader(header); err != nil {
			return nil, "", -1, err
		}

		name := http.CanonicalHeaderKey(header.Name)
		switch name {
		case "Host":
			if hasHost {
				return nil, "", -1, fmt.Errorf("duplicate Host header")
			}
			hasHost = true
			host = header.Value
		case "Content-Length":
			if hasTransferEncoding {
				return nil, "", -1, fmt.Errorf("conflicting Content-Length and Transfer-Encoding")
			}
			parsedLen, err := strconv.ParseInt(strings.TrimSpace(header.Value), 10, 64)
			if err != nil {
				return nil, "", -1, fmt.Errorf("failed to parse content len `%s`: %w", header.Value, err)
			}
			if parsedLen < 0 {
				return nil, "", -1, fmt.Errorf("failed to parse content len: should be >= 0")
			}
			if hasContentLength && parsedLen != contentLen {
				return nil, "", -1, fmt.Errorf("conflicting Content-Length headers")
			}
			hasContentLength = true
			contentLen = parsedLen
		case "Transfer-Encoding":
			if hasContentLength {
				return nil, "", -1, fmt.Errorf("conflicting Content-Length and Transfer-Encoding")
			}
			hasTransferEncoding = true
		}

		headers.Add(name, header.Value)
	}

	return headers, host, contentLen, nil
}

func sendHTTPErrorResponse(client RLDP, query *rldp.Query, transferId []byte, version string, statusCode int) error {
	if version == "" {
		version = "HTTP/1.1"
	}
	reason := http.StatusText(statusCode)
	if reason == "" {
		reason = "Error"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := client.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferId, Response{
		Version:    version,
		StatusCode: int32(statusCode),
		Reason:     reason,
		NoPayload:  true,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("failed to send HTTP %d response for %s query: %w", statusCode, hex.EncodeToString(query.ID), err)
	}
	return nil
}

func NewServer(key ed25519.PrivateKey, gate *adnl.Gateway, dht DHT, handler http.Handler) *Server {
	return newServer(key, gate, dht, handler, DefaultMaxConcurrentRequests)
}

// NewServerWithMaxConcurrentRequests creates a server with one concurrency limit shared by all peers.
func NewServerWithMaxConcurrentRequests(
	key ed25519.PrivateKey,
	gate *adnl.Gateway,
	dht DHT,
	handler http.Handler,
	maxConcurrentRequests int,
) (*Server, error) {
	if maxConcurrentRequests <= 0 {
		return nil, fmt.Errorf("max concurrent requests must be greater than zero, got %d", maxConcurrentRequests)
	}

	return newServer(key, gate, dht, handler, maxConcurrentRequests), nil
}

func newServer(
	key ed25519.PrivateKey,
	gate *adnl.Gateway,
	dht DHT,
	handler http.Handler,
	maxConcurrentRequests int,
) *Server {
	return &Server{
		key:            key,
		dht:            dht,
		handler:        handler,
		rldpInfos:      map[string]*rldpInfo{},
		activeRequests: newActiveRequestRegistry(),
		dispatcher:     newRequestDispatcher(maxConcurrentRequests),
		closer:         make(chan bool, 1),
		Timeout:        30 * time.Second,
		adnlServer:     gate,
	}
}

func (s *Server) ListenAndServe(listenAddr string) error {
	go func() {
		for {
			select {
			case <-s.closer:
				return
			case <-time.After(5 * time.Second):
			}

			now := time.Now()

			for _, stream := range s.activeRequests.expired(now) {
				stream.finish()
			}
		}
	}()

	go func() {
		wait := 1 * time.Second
		// refresh dht records
		for {
			select {
			case <-s.closer:
				return
			case <-time.After(wait):
			}

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
			err := s.updateDHT(ctx)
			cancel()

			if err != nil {
				Logger("DHT ADNL address record update failed: ", err, ". We will retry in 5 sec")

				// on err, retry sooner
				wait = 5 * time.Second
				continue
			}
			wait = 1 * time.Minute
		}
	}()

	s.adnlServer.SetConnectionHandler(func(client adnl.Peer) error {
		adnlAddr, err := SerializeADNLAddress(client.GetID())
		if err != nil {
			return err
		}

		previousHandler := client.GetQueryHandler()
		client.SetQueryHandler(func(query *adnl.MessageQuery) error {
			switch query.Data.(type) {
			case GetCapabilities:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := client.Answer(ctx, query.ID, &Capabilities{Value: CapabilityRLDP2})
				cancel()
				if err != nil {
					return fmt.Errorf("failed to send capabilities answer: %w", err)
				}
				return nil
			}
			if previousHandler != nil {
				return previousHandler(query)
			}
			return fmt.Errorf("unexpected query type %s", reflect.TypeOf(query.Data))
		})

		rl := newRLDP(client, true)
		rl.SetOnQuery(s.handle(rl, adnlAddr, client.RemoteAddr()))
		return nil
	})

	err := s.adnlServer.StartServer(listenAddr, runtime.NumCPU())
	if err != nil {
		_ = s.Stop()
		return err
	}

	<-s.closer
	return nil
}

func (s *Server) Address() []byte {
	return s.adnlServer.GetID()
}

func (s *Server) updateDHT(ctx context.Context) error {
	addr := s.adnlServer.GetAddressList()

	ctxStore, cancel := context.WithTimeout(ctx, 80*time.Second)
	stored, id, err := s.dht.StoreAddress(ctxStore, addr, 15*time.Minute, s.key)
	cancel()
	if err != nil && stored == 0 {
		return err
	}

	// make sure it was saved
	_, _, err = s.dht.FindAddresses(ctx, id)
	if err != nil {
		return err
	}

	if len(addr.Addresses) == 0 {
		return fmt.Errorf("no addresses found for %s", hex.EncodeToString(id))
	}

	ip := adnladdress.IPValue(addr.Addresses[0])
	if ip == nil {
		return fmt.Errorf("no ip found for %s address %T", hex.EncodeToString(id), addr.Addresses[0])
	}

	Logger("DHT ADNL address record for TON Site was refreshed successfully on", stored,
		"nodes to ip", ip.String(), "with port", adnladdress.PortValue(addr.Addresses[0]))
	return nil
}

func (s *Server) Stop() (err error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if !s.closed {
		s.closed = true
		if s.dispatcher != nil {
			s.dispatcher.stop()
		}
		close(s.closer)
		for _, stream := range s.activeRequests.drain() {
			stream.finish()
		}
		if s.dht != nil {
			s.dht.Close()
		}

		if s.adnlServer != nil {
			err = s.adnlServer.Close()
		}
	}
	return
}

func (s *Server) registerPayloadStream(
	key string,
	stream *payloadStream,
	lease *requestLease,
) error {
	s.mx.RLock()
	if s.closed {
		s.mx.RUnlock()
		return ErrServerStopped
	}
	if lease != nil {
		lease.retainForResponse()
		stream.lease = lease
	}
	previous := s.activeRequests.store(key, stream)
	s.mx.RUnlock()

	if previous != nil {
		previous.finish()
	}
	return nil
}

func cloneQuery(query *rldp.Query) *rldp.Query {
	cloned := *query
	cloned.ID = bytes.Clone(query.ID)

	switch data := query.Data.(type) {
	case Request:
		headers := data.Headers
		data.ID = bytes.Clone(data.ID)
		data.Method = strings.Clone(data.Method)
		data.URL = strings.Clone(data.URL)
		data.Version = strings.Clone(data.Version)
		data.Headers = make([]Header, len(headers))
		for i, header := range headers {
			data.Headers[i] = Header{
				Name:  strings.Clone(header.Name),
				Value: strings.Clone(header.Value),
			}
		}
		cloned.Data = data
	case GetNextPayloadPart:
		data.ID = bytes.Clone(data.ID)
		cloned.Data = data
	}

	return &cloned
}

func (s *Server) handle(client RLDP, adnlId, addr string) func(transferId []byte, msg *rldp.Query) error {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return func([]byte, *rldp.Query) error {
			return fmt.Errorf("failed to parse remote addr `%s`: %w", addr, err)
		}
	}
	netAddr := net.UDPAddrFromAddrPort(addrPort)

	return func(transferId []byte, query *rldp.Query) error {
		if query == nil {
			return errors.New("nil RLDP HTTP query")
		}

		dispatcher := s.dispatcher
		if dispatcher == nil {
			return errors.New("RLDP HTTP request dispatcher is not initialized")
		}

		var lease *requestLease
		var continuation *payloadStream
		switch req := query.Data.(type) {
		case Request:
			if err := dispatcher.acquire(); err != nil {
				return err
			}
			lease = newRequestLease(dispatcher)
		case GetNextPayloadPart:
			// A payload-part query continues an already admitted logical HTTP
			// request. Charging another slot here can deadlock a full server:
			// every response writer holds a slot while getNext cannot drain it.
			if err := dispatcher.checkRunning(); err != nil {
				return err
			}
			requestKey := hex.EncodeToString(req.ID)
			stream, exists := s.activeRequests.claimContinuation(
				requestKey,
				time.Now().Add(s.Timeout),
			)
			if !exists {
				return fmt.Errorf("unknown request id %s", requestKey)
			}
			if stream == nil {
				return errPayloadContinuationInProgress
			}
			continuation = stream
		default:
			return nil
		}

		// RLDP parses incoming TL data without copying it, so the goroutine must own
		// every byte and string it reads after this callback returns.
		ownedTransferId := bytes.Clone(transferId)
		ownedQuery := cloneQuery(query)
		go s.runQuery(lease, continuation, client, adnlId, netAddr, ownedTransferId, ownedQuery)
		return nil
	}
}

func (s *Server) runQuery(
	lease *requestLease,
	continuation *payloadStream,
	client RLDP,
	adnlId string,
	netAddr *net.UDPAddr,
	transferId []byte,
	query *rldp.Query,
) {
	if lease != nil {
		defer lease.release()
	}
	if continuation != nil {
		defer continuation.finishContinuation()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			Logger("panic while handling RLDP HTTP query: ", recovered, "\n", string(debug.Stack()))
		}
	}()

	if err := s.handleQuery(lease, continuation, client, adnlId, netAddr, transferId, query); err != nil {
		Logger("failed to handle RLDP HTTP query: ", err)
	}
}

func (s *Server) handleQuery(
	lease *requestLease,
	continuation *payloadStream,
	client RLDP,
	adnlId string,
	netAddr *net.UDPAddr,
	transferId []byte,
	query *rldp.Query,
) error {
	switch req := query.Data.(type) {
	case Request:
		uri, err := url.Parse(req.URL)
		if err != nil {
			Logger("bad HTTP request over RLDP: failed to parse url", req.URL, err)
			return sendHTTPErrorResponse(client, query, transferId, req.Version, http.StatusBadRequest)
		}
		uri.Scheme = "http"

		headers, host, contentLen, err := parseRequestHeaders(req.Headers)
		if err != nil {
			Logger("bad HTTP request over RLDP:", err)
			return sendHTTPErrorResponse(client, query, transferId, req.Version, http.StatusBadRequest)
		}
		if host != "" {
			uri.Host = host
		}
		headers.Set("X-Adnl-Ip", netAddr.IP.String())
		headers.Set("X-Adnl-Id", adnlId)

		ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
		defer cancel()

		reqBody := newDataStreamer()
		if req.Method == "CONNECT" ||
			len(headers["Content-Length"]) > 0 ||
			len(headers["Transfer-Encoding"]) > 0 {
			// request should have payload, fetch it in parallel and write to stream
			go func() {
				if fetchErr := s.fetchPayload(ctx, req.ID, client, reqBody); fetchErr != nil {
					reqBody.Close()
					return
				}
				reqBody.Finish()
			}()
		} else {
			reqBody.Finish()
		}

		httpReq := &http.Request{
			Method:        req.Method,
			URL:           uri,
			Proto:         req.Version,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        headers,
			Body:          reqBody,
			ContentLength: contentLen,
			Host:          uri.Host,
			RemoteAddr:    netAddr.IP.String(),
			RequestURI:    uri.RequestURI(),
		}

		stream := newDataStreamer()

		wb := &writerBuff{
			client:      client,
			server:      s,
			stream:      stream,
			maxAnswerSz: query.MaxAnswerSize,
			timeout:     query.Timeout,
			queryId:     query.ID,
			requestId:   req.ID,
			transferId:  transferId,
			lease:       lease,
		}

		w := &respWriter{
			writer:  bufio.NewWriterSize(wb, _ChunkSize),
			wb:      wb,
			headers: map[string][]string{},
		}
		wb.resp = w
		completed := false
		defer func() {
			if !completed {
				wb.abortResponse()
			}
		}()

		s.handler.ServeHTTP(w, httpReq)
		wb.handled = true
		if w.err != nil {
			return fmt.Errorf("failed to flush response for `%s`: %w", uri, w.err)
		}
		// flush write buffer, to commit data
		err = w.writer.Flush()
		if err != nil {
			return fmt.Errorf("failed to flush response buffer for `%s`: %w", uri, err)
		}

		// if no data was committed - it will send empty response
		err = wb.flush(nil, false)
		if err != nil {
			return fmt.Errorf("failed to flush response for `%s`: %w", uri, err)
		}
		stream.Finish()
		completed = true
	case GetNextPayloadPart:
		requestKey := hex.EncodeToString(req.ID)
		stream := continuation
		if stream == nil {
			stream = s.activeRequests.getAndRefresh(requestKey, time.Now().Add(s.Timeout))
		}

		if stream == nil {
			return fmt.Errorf("unknown request id %s", requestKey)
		}

		part, err := handleGetPart(req, stream)
		if err != nil {
			return fmt.Errorf("handle part err: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
		err = client.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferId, part)
		cancel()
		if err != nil {
			s.activeRequests.deleteIfSame(requestKey, stream)
			stream.finish()
			return fmt.Errorf("failed to send answer: %w", err)
		}

		if part.IsLast {
			s.activeRequests.deleteIfSame(requestKey, stream)
			stream.finish()
		}
	}
	return nil
}

func (s *Server) fetchPayload(ctx context.Context, requestID []byte, client RLDP, w io.Writer) error {
	var seqno int32 = 0
	last := false
	for !last {
		var part PayloadPart
		err := client.DoQuery(ctx, _RLDPMaxAnswerSize, GetNextPayloadPart{
			ID:           requestID,
			Seqno:        seqno,
			MaxChunkSize: _ChunkSize,
		}, &part)
		if err != nil {
			return err
		}

		last = part.IsLast
		_, err = w.Write(part.Data)
		if err != nil {
			return err
		}

		seqno++
	}
	return nil
}

func (r *respWriter) Header() http.Header {
	return r.headers
}

func (r *respWriter) Write(bytes []byte) (int, error) {
	return r.writer.Write(bytes)
}

func (r *respWriter) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *respWriter) Flush() {
	if err := r.writer.Flush(); err != nil {
		r.err = err
		return
	}
	if err := r.wb.flushReader(); err != nil {
		r.err = err
		return
	}
	if err := r.wb.flush(nil, true); err != nil {
		r.err = err
	}
}

func (w *writerBuff) Write(bytes []byte) (n int, err error) {
	if len(bytes) == 0 {
		return 0, nil
	}

	w.mx.Lock()
	defer w.mx.Unlock()

	if err := w.flush(bytes, false); err != nil {
		return 0, err
	}

	n, err = w.stream.Write(bytes)
	if n > 0 {
		w.flushReaderPendingBytes += int64(n)
	}
	return n, err
}

func (w *writerBuff) flushReader() error {
	w.mx.Lock()
	defer w.mx.Unlock()

	if w.flushReaderPendingBytes == 0 {
		return nil
	}
	pending := w.flushReaderPendingBytes
	w.flushReaderPendingBytes = 0
	if pending%_ChunkSize == 0 {
		return nil
	}
	return w.stream.FlushReader()
}

func (w *writerBuff) abortResponse() {
	if w.registered != nil {
		w.server.activeRequests.deleteIfSame(hex.EncodeToString(w.requestId), w.registered)
		w.registered.finish()
		return
	}
	_ = w.stream.Close()
}

func (w *writerBuff) flush(payload []byte, forcePayload bool) error {
	if w.headerSent {
		return nil
	}
	w.headerSent = true
	hasPayload := forcePayload || len(payload) > 0

	if w.handled {
		// if it is first and last write - we can define content length
		if !hasPayload && w.resp.headers.Get("Content-Length") == "" {
			w.resp.headers.Set("Content-Length", "0")
		} else if !strings.Contains(strings.ToLower(w.resp.headers.Get("Transfer-Encoding")), "chunked") {
			w.resp.headers.Set("Content-Length", fmt.Sprint(len(payload)))
		}
	} else {
		if w.resp.headers.Get("Content-Length") == "" && w.resp.headers.Get("Transfer-Encoding") == "" {
			// if it is not last write (flush inside handler), we use chunked transfer
			w.resp.headers.Set("Transfer-Encoding", "chunked")
		}
	}

	if w.resp.statusCode <= 0 {
		w.resp.statusCode = 200
	}

	var headers []Header
	for k, v := range w.resp.headers {
		for _, hdr := range v {
			headers = append(headers, Header{
				Name:  k,
				Value: hdr,
			})
		}
	}

	var registeredStream *payloadStream
	requestKey := hex.EncodeToString(w.requestId)
	if hasPayload {
		candidate := &payloadStream{
			Data:      w.stream,
			ValidTill: time.Now().Add(w.server.Timeout),
		}
		if err := w.server.registerPayloadStream(requestKey, candidate, w.lease); err != nil {
			_ = w.stream.Close()
			return fmt.Errorf("failed to register response stream: %w", err)
		}
		registeredStream = candidate
		w.registered = candidate
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := w.client.SendAnswer(ctx, w.maxAnswerSz, w.timeout, w.queryId, w.transferId, Response{
		Version:    "HTTP/1.1",
		StatusCode: int32(w.resp.statusCode),
		Reason:     http.StatusText(w.resp.statusCode),
		Headers:    headers,
		NoPayload:  !hasPayload,
	})
	cancel()
	if err != nil {
		if registeredStream != nil {
			w.server.activeRequests.deleteIfSame(requestKey, registeredStream)
			registeredStream.finish()
		} else {
			_ = w.stream.Close()
		}
		return fmt.Errorf("failed to send response for %s query: %w", hex.EncodeToString(w.queryId), err)
	}

	return nil
}
