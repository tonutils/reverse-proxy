package rldphttp

import (
	"io"
	"sync"
	"time"
)

type payloadStream struct {
	nextOffset int
	Data       io.ReadCloser
	ValidTill  time.Time

	mx sync.Mutex
}

type dataStreamer struct {
	parts  chan []byte
	closer chan struct{}

	mx      sync.Mutex
	readMx  sync.Mutex
	writeMx sync.Mutex

	buf      []byte
	finished bool
	closed   bool
}

func newDataStreamer() *dataStreamer {
	return &dataStreamer{
		parts:  make(chan []byte, 16),
		closer: make(chan struct{}),
	}
}

func (d *dataStreamer) Read(p []byte) (int, error) {
	d.readMx.Lock()
	defer d.readMx.Unlock()

	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			select {
			case chunk, ok := <-d.parts:
				if !ok {
					return n, io.EOF
				}
				if chunk == nil {
					return n, nil
				}
				d.buf = chunk
			case <-d.closer:
				return n, io.ErrUnexpectedEOF
			}
		}

		copied := copy(p[n:], d.buf)
		d.buf = d.buf[copied:]
		n += copied
	}
	return n, nil
}

func (d *dataStreamer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	d.writeMx.Lock()
	defer d.writeMx.Unlock()

	d.mx.Lock()
	if d.finished {
		d.mx.Unlock()
		return 0, io.ErrClosedPipe
	}
	d.mx.Unlock()

	chunk := append([]byte(nil), data...)

	select {
	case d.parts <- chunk:
		return len(data), nil
	case <-d.closer:
		return 0, io.ErrClosedPipe
	}
}

func (d *dataStreamer) FlushReader() {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.finished {
		return
	}

	select {
	case d.parts <- nil:
	default:
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
