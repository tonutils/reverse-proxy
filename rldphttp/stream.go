package rldphttp

import (
	"io"
	"sync"
	"time"
)

type payloadStream struct {
	nextSeqno int32
	Data      io.ReadCloser
	ValidTill time.Time

	mx     sync.Mutex
	readMx sync.Mutex
}

type streamChunk struct {
	data []byte
}

var streamChunkPool = sync.Pool{
	New: func() any {
		return &streamChunk{
			data: make([]byte, 0, _ChunkSize),
		}
	},
}

type dataStreamer struct {
	parts  chan *streamChunk
	closer chan struct{}

	mx      sync.Mutex
	readMx  sync.Mutex
	writeMx sync.Mutex

	buf      []byte
	bufChunk *streamChunk
	finished bool
	closed   bool
}

func newDataStreamer() *dataStreamer {
	return &dataStreamer{
		parts:  make(chan *streamChunk, 16),
		closer: make(chan struct{}),
	}
}

func getStreamChunk(size int) *streamChunk {
	if size <= _ChunkSize {
		chunk := streamChunkPool.Get().(*streamChunk)
		chunk.data = chunk.data[:size]
		return chunk
	}

	return &streamChunk{
		data: make([]byte, size),
	}
}

func putStreamChunk(chunk *streamChunk) {
	if chunk == nil || cap(chunk.data) != _ChunkSize {
		return
	}

	chunk.data = chunk.data[:0]
	streamChunkPool.Put(chunk)
}

func (d *dataStreamer) releaseReadChunk() {
	if d.bufChunk == nil || len(d.buf) > 0 {
		return
	}

	putStreamChunk(d.bufChunk)
	d.bufChunk = nil
}

func (d *dataStreamer) Read(p []byte) (int, error) {
	d.readMx.Lock()
	defer d.readMx.Unlock()

	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			d.releaseReadChunk()

			select {
			case chunk, ok := <-d.parts:
				if !ok {
					return n, io.EOF
				}
				if chunk == nil {
					return n, nil
				}
				d.buf = chunk.data
				d.bufChunk = chunk
			case <-d.closer:
				return n, io.ErrUnexpectedEOF
			}
		}

		copied := copy(p[n:], d.buf)
		d.buf = d.buf[copied:]
		n += copied
		d.releaseReadChunk()
	}
	return n, nil
}

func (d *dataStreamer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	d.writeMx.Lock()
	defer d.writeMx.Unlock()

	written := 0
	for len(data) > 0 {
		d.mx.Lock()
		if d.finished || d.closed {
			d.mx.Unlock()
			if written > 0 {
				return written, io.ErrClosedPipe
			}
			return 0, io.ErrClosedPipe
		}
		d.mx.Unlock()

		size := len(data)
		if size > _ChunkSize {
			size = _ChunkSize
		}
		chunk := getStreamChunk(size)
		copy(chunk.data, data[:size])

		select {
		case d.parts <- chunk:
			written += size
			data = data[size:]
		case <-d.closer:
			putStreamChunk(chunk)
			if written > 0 {
				return written, io.ErrClosedPipe
			}
			return 0, io.ErrClosedPipe
		}
	}

	return written, nil
}

func (d *dataStreamer) FlushReader() error {
	d.writeMx.Lock()
	defer d.writeMx.Unlock()

	d.mx.Lock()
	if d.finished {
		d.mx.Unlock()
		return nil
	}
	if d.closed {
		d.mx.Unlock()
		return io.ErrClosedPipe
	}
	d.mx.Unlock()

	select {
	case d.parts <- nil:
		return nil
	case <-d.closer:
		return io.ErrClosedPipe
	}
}

func (d *dataStreamer) Finish() {
	d.writeMx.Lock()
	defer d.writeMx.Unlock()

	d.mx.Lock()
	if d.finished {
		d.mx.Unlock()
		return
	}
	d.finished = true
	d.mx.Unlock()

	close(d.parts)
}

func (d *dataStreamer) Close() error {
	d.mx.Lock()
	if d.closed {
		d.mx.Unlock()
		return nil
	}
	d.closed = true
	d.mx.Unlock()

	close(d.closer)
	return nil
}
