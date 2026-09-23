package mstp

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrDuplicateMAC = errors.New("BACnet MS/TP duplicate local MAC detected")
	ErrQueueFull    = errors.New("BACnet MS/TP transmit queue is full")
)

type MasterConfig struct {
	LocalMAC          byte
	MaxMaster         byte
	MaxInfoFrames     int
	MaxPending        int
	ReplyTimeout      time.Duration
	UsageTimeout      time.Duration
	TokenRetryTimeout time.Duration
	PollInterval      time.Duration
	NoTokenTimeout    time.Duration
}

type pendingFrame struct {
	destination byte
	data        []byte
	expectReply bool
}

type masterWait uint8

const (
	waitNone masterWait = iota
	waitUsage
	waitReply
	waitPoll
)

// Master is a deterministic MS/TP token-master protocol core. It performs no
// I/O: callers feed decoded frames to Handle, advance time with Tick, and send
// the returned frames in order.
type Master struct {
	config       MasterConfig
	pending      []pendingFrame
	hasToken     bool
	wait         masterWait
	waitUntil    time.Time
	lastActivity time.Time
	framesSent   int
	pollTarget   byte
	nextMaster   *byte
}

func NewMaster(config MasterConfig, now time.Time) (*Master, error) {
	if err := validateMasterConfig(config); err != nil {
		return nil, err
	}
	return &Master{
		config:       config,
		lastActivity: now,
		pollTarget:   nextMAC(config.LocalMAC, config.MaxMaster),
	}, nil
}

func validateMasterConfig(config MasterConfig) error {
	if config.LocalMAC > 127 {
		return errors.New("MS/TP local MAC must be 0..127")
	}
	if config.MaxMaster > 127 || config.MaxMaster < config.LocalMAC {
		return errors.New("MS/TP max master must be between local MAC and 127")
	}
	if config.MaxInfoFrames < 1 || config.MaxInfoFrames > 255 {
		return errors.New("MS/TP max info frames must be 1..255")
	}
	if config.MaxPending < 1 {
		return errors.New("MS/TP max pending must be positive")
	}
	if config.ReplyTimeout <= 0 || config.UsageTimeout <= 0 || config.TokenRetryTimeout <= 0 || config.PollInterval <= 0 || config.NoTokenTimeout <= 0 {
		return errors.New("MS/TP timeouts must be positive")
	}
	if config.ReplyTimeout <= config.UsageTimeout {
		return errors.New("MS/TP reply timeout must exceed usage timeout")
	}
	if config.NoTokenTimeout <= config.TokenRetryTimeout {
		return errors.New("MS/TP no-token timeout must exceed token retry timeout")
	}
	return nil
}

func (m *Master) Enqueue(destination byte, data []byte, expectReply bool) error {
	if destination == 255 && expectReply {
		return errors.New("BACnet MS/TP broadcast cannot expect a reply")
	}
	if len(data) == 0 || len(data) > MaxDataLength {
		return fmt.Errorf("BACnet MS/TP NPDU must contain 1..%d bytes", MaxDataLength)
	}
	if len(m.pending) >= m.config.MaxPending {
		return ErrQueueFull
	}
	m.pending = append(m.pending, pendingFrame{
		destination: destination,
		data:        append([]byte(nil), data...),
		expectReply: expectReply,
	})
	return nil
}

func (m *Master) Handle(frame Frame, now time.Time) ([]Frame, error) {
	if frame.Source == m.config.LocalMAC {
		return nil, ErrDuplicateMAC
	}
	m.lastActivity = now
	if frame.Destination != m.config.LocalMAC && frame.Destination != 255 {
		return nil, nil
	}
	switch frame.Type {
	case FrameToken:
		if frame.Destination != m.config.LocalMAC {
			return nil, nil
		}
		m.hasToken, m.wait, m.framesSent = true, waitNone, 0
		return m.advance(now), nil
	case FramePollForMaster:
		if frame.Destination == m.config.LocalMAC {
			return []Frame{m.control(FrameReplyToPollForMaster, frame.Source)}, nil
		}
	case FrameReplyToPollForMaster:
		if m.hasToken && m.wait == waitPoll && frame.Source == m.pollTarget {
			next := frame.Source
			m.nextMaster = &next
			m.hasToken, m.wait = false, waitNone
			return []Frame{m.control(FrameToken, next)}, nil
		}
	case FrameDataExpectingReply:
		if frame.Destination == m.config.LocalMAC {
			return []Frame{m.control(FrameReplyPostponed, frame.Source)}, nil
		}
	case FrameDataNotExpectingReply:
		if m.hasToken && m.wait == waitReply {
			m.wait = waitNone
			return m.advance(now), nil
		}
	}
	return nil, nil
}

func (m *Master) Tick(now time.Time) []Frame {
	if m.hasToken && m.wait != waitNone {
		if now.Before(m.waitUntil) {
			return nil
		}
		if m.wait == waitPoll {
			m.pollTarget = nextMAC(m.pollTarget, m.config.MaxMaster)
			if m.pollTarget == m.config.LocalMAC {
				m.framesSent = 0
				m.wait, m.waitUntil = waitUsage, now.Add(m.config.PollInterval)
				return nil
			}
			m.waitUntil = now.Add(m.config.PollInterval)
			return []Frame{m.control(FramePollForMaster, m.pollTarget)}
		}
		m.wait = waitNone
		return m.advance(now)
	}
	if m.hasToken {
		return m.advance(now)
	}
	recoveryAt := m.lastActivity.Add(m.config.NoTokenTimeout + time.Duration(m.config.LocalMAC)*m.config.TokenRetryTimeout)
	if now.Before(recoveryAt) {
		return nil
	}
	m.hasToken, m.framesSent = true, 0
	return m.advance(now)
}

func (m *Master) advance(now time.Time) []Frame {
	if !m.hasToken {
		return nil
	}
	if len(m.pending) > 0 && m.framesSent < m.config.MaxInfoFrames {
		pending := m.pending[0]
		m.pending = m.pending[1:]
		m.framesSent++
		m.lastActivity = now
		kind := byte(FrameDataNotExpectingReply)
		m.wait, m.waitUntil = waitUsage, now.Add(m.config.UsageTimeout)
		if pending.expectReply {
			kind = FrameDataExpectingReply
			m.wait, m.waitUntil = waitReply, now.Add(m.config.ReplyTimeout)
		}
		return []Frame{{Type: kind, Destination: pending.destination, Source: m.config.LocalMAC, Data: pending.data}}
	}
	if m.nextMaster != nil && *m.nextMaster != m.config.LocalMAC {
		next := *m.nextMaster
		m.lastActivity = now
		m.hasToken, m.wait = false, waitNone
		return []Frame{m.control(FrameToken, next)}
	}
	m.pollTarget = nextMAC(m.config.LocalMAC, m.config.MaxMaster)
	if m.pollTarget == m.config.LocalMAC {
		m.hasToken = false
		return nil
	}
	m.wait, m.waitUntil = waitPoll, now.Add(m.config.PollInterval)
	m.lastActivity = now
	return []Frame{m.control(FramePollForMaster, m.pollTarget)}
}

func (m *Master) control(kind, destination byte) Frame {
	return Frame{Type: kind, Destination: destination, Source: m.config.LocalMAC}
}

func nextMAC(current, max byte) byte {
	if current >= max {
		return 0
	}
	return current + 1
}
