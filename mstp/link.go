package mstp

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

var (
	ErrLinkClosed  = errors.New("BACnet MS/TP link is closed")
	ErrInboundFull = errors.New("BACnet MS/TP inbound queue is full")
)

type DeadlineSession interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
}

type LinkConfig struct {
	Master           MasterConfig
	ReadPollInterval time.Duration
	WriteTimeout     time.Duration
	ReadBufferSize   int
	MaxInbound       int
}

type Packet struct {
	Source byte
	Data   []byte
}

type linkSend struct {
	ctx         context.Context
	destination byte
	data        []byte
	expectReply bool
	result      chan error
}

// Link serializes all MS/TP protocol state and session I/O in Run. The caller
// retains ownership of opening and closing the underlying serial session.
type Link struct {
	config  LinkConfig
	session DeadlineSession
	master  *Master
	decoder *Decoder
	send    chan linkSend
	inbound chan Packet
	done    chan struct{}

	runMu   sync.Mutex
	running bool
}

func NewLink(config LinkConfig, session DeadlineSession) (*Link, error) {
	if session == nil {
		return nil, errors.New("BACnet MS/TP deadline session is required")
	}
	if config.ReadPollInterval <= 0 || config.WriteTimeout <= 0 {
		return nil, errors.New("BACnet MS/TP link timeouts must be positive")
	}
	if config.ReadBufferSize < 8 {
		return nil, errors.New("BACnet MS/TP read buffer must be at least 8 bytes")
	}
	if config.MaxInbound < 1 {
		return nil, errors.New("BACnet MS/TP max inbound must be positive")
	}
	master, err := NewMaster(config.Master, time.Now())
	if err != nil {
		return nil, err
	}
	return &Link{
		config: config, session: session, master: master,
		decoder: NewDecoder(MaxDataLength), send: make(chan linkSend, config.Master.MaxPending),
		inbound: make(chan Packet, config.MaxInbound), done: make(chan struct{}),
	}, nil
}

func (l *Link) Send(ctx context.Context, destination byte, data []byte, expectReply bool) error {
	if ctx == nil {
		return errors.New("BACnet MS/TP send context is required")
	}
	request := linkSend{
		ctx: ctx, destination: destination, data: append([]byte(nil), data...),
		expectReply: expectReply, result: make(chan error, 1),
	}
	select {
	case <-l.done:
		return ErrLinkClosed
	case <-ctx.Done():
		return ctx.Err()
	case l.send <- request:
	}
	select {
	case <-l.done:
		return ErrLinkClosed
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.result:
		return err
	}
}

func (l *Link) Inbound() <-chan Packet { return l.inbound }

func (l *Link) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("BACnet MS/TP run context is required")
	}
	l.runMu.Lock()
	if l.running {
		l.runMu.Unlock()
		return errors.New("BACnet MS/TP link is already running")
	}
	l.running = true
	l.runMu.Unlock()

	defer close(l.done)
	defer close(l.inbound)
	watcherDone := make(chan struct{})
	defer close(watcherDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.session.SetDeadline(time.Now())
		case <-watcherDone:
		}
	}()

	buffer := make([]byte, l.config.ReadBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.drainSends()
		if err := l.writeFrames(ctx, l.master.Tick(time.Now())); err != nil {
			return err
		}
		if err := l.session.SetDeadline(time.Now().Add(l.config.ReadPollInterval)); err != nil {
			return err
		}
		n, readErr := l.session.Read(buffer)
		if n > 0 {
			if err := l.handleFrames(ctx, l.decoder.Feed(buffer[:n])); err != nil {
				return err
			}
		}
		if readErr != nil && !isTimeout(readErr) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return readErr
		}
	}
}

func (l *Link) drainSends() {
	for {
		select {
		case request := <-l.send:
			if err := request.ctx.Err(); err != nil {
				request.result <- err
				continue
			}
			request.result <- l.master.Enqueue(request.destination, request.data, request.expectReply)
		default:
			return
		}
	}
}

func (l *Link) handleFrames(ctx context.Context, frames []Frame) error {
	for _, frame := range frames {
		outputs, err := l.master.Handle(frame, time.Now())
		if err != nil {
			return err
		}
		if err = l.writeFrames(ctx, outputs); err != nil {
			return err
		}
		if (frame.Type == FrameDataExpectingReply || frame.Type == FrameDataNotExpectingReply) &&
			(frame.Destination == l.config.Master.LocalMAC || frame.Destination == 255) {
			packet := Packet{Source: frame.Source, Data: append([]byte(nil), frame.Data...)}
			select {
			case l.inbound <- packet:
			default:
				return ErrInboundFull
			}
		}
	}
	return nil
}

func (l *Link) writeFrames(ctx context.Context, frames []Frame) error {
	for _, frame := range frames {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := EncodeFrame(frame)
		if err != nil {
			return err
		}
		if err = l.session.SetDeadline(time.Now().Add(l.config.WriteTimeout)); err != nil {
			return err
		}
		for len(raw) > 0 {
			n, writeErr := l.session.Write(raw)
			if writeErr != nil {
				return writeErr
			}
			if n <= 0 {
				return errors.New("BACnet MS/TP session write made no progress")
			}
			raw = raw[n:]
		}
	}
	return nil
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
