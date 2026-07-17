package rldphttp

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton/dns"
	"io"
	"sync"
	"time"
)

const _ChunkSize = 1 << 20
const _RLDPMaxAnswerSize = 2*_ChunkSize + 1024

type DHT interface {
	StoreAddress(ctx context.Context, addresses address.List, ttl time.Duration, ownerKey ed25519.PrivateKey) (int, []byte, error)
	FindAddresses(ctx context.Context, key []byte) (*address.List, ed25519.PublicKey, error)
	Close()
}

type Resolver interface {
	Resolve(ctx context.Context, domain string) (*dns.Domain, error)
}

type RLDP interface {
	Close()
	DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error
	SetOnQuery(handler func(transferId []byte, query *rldp.Query) error)
	SetOnDisconnect(handler func())
	SendAnswer(ctx context.Context, maxAnswerSize uint64, timeout uint32, queryId, transferId []byte, answer tl.Serializable) error
}

type ADNL interface {
	GetID() []byte
	RemoteAddr() string
	Query(ctx context.Context, req, result tl.Serializable) error
	SetDisconnectHandler(handler func(addr string, key ed25519.PublicKey))
	GetDisconnectHandler() func(addr string, key ed25519.PublicKey)
	SetCustomMessageHandler(handler func(msg *adnl.MessageCustom) error)
	SendCustomMessage(ctx context.Context, req tl.Serializable) error
	SetQueryHandler(handler func(msg *adnl.MessageQuery) error)
	GetQueryHandler() func(msg *adnl.MessageQuery) error
	Answer(ctx context.Context, queryID []byte, result tl.Serializable) error
	GetCloserCtx() context.Context
	Close()
}

var newRLDP = func(a ADNL, v2 bool) RLDP {
	if v2 {
		return rldp.NewClientV2(a)
	}
	return rldp.NewClient(a)
}

type rldpInfo struct {
	mx             sync.RWMutex
	ActiveClient   RLDP
	ClientLastUsed time.Time

	ID   ed25519.PublicKey
	Addr string

	Resolved bool
}

func (r *rldpInfo) destroyClient(rl RLDP) {
	rl.Close()

	r.mx.Lock()
	if r.ActiveClient == rl {
		r.ActiveClient = nil
	}
	r.mx.Unlock()
}

func handleGetPart(req GetNextPayloadPart, stream *payloadStream) (*PayloadPart, error) {
	if req.Seqno < 0 {
		return nil, fmt.Errorf("failed to get part for stream %s, seqno should be >= 0", hex.EncodeToString(req.ID))
	}
	if req.MaxChunkSize <= 0 {
		return nil, fmt.Errorf("failed to get part for stream %s, max chunk size should be > 0", hex.EncodeToString(req.ID))
	}
	chunkSize := req.MaxChunkSize
	if chunkSize > _ChunkSize {
		chunkSize = _ChunkSize
	}

	stream.readMx.Lock()
	defer stream.readMx.Unlock()

	stream.mx.Lock()
	expectedSeqno := stream.nextSeqno
	stream.mx.Unlock()
	if req.Seqno != expectedSeqno {
		return nil, fmt.Errorf("failed to get part for stream %s, incorrect seqno %d, should be %d", hex.EncodeToString(req.ID), req.Seqno, expectedSeqno)
	}

	var last bool
	data := make([]byte, int(chunkSize))
	n, err := stream.Data.Read(data)
	if err != nil {
		if err != io.EOF {
			return nil, fmt.Errorf("failed to read chunk %d, err: %w", req.Seqno, err)
		}
		last = true
	}

	stream.mx.Lock()
	stream.nextSeqno++
	stream.mx.Unlock()

	return &PayloadPart{
		Data:    data[:n],
		Trailer: nil, // TODO: trailer
		IsLast:  last,
	}, nil
}
