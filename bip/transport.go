package bip

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/log"
	"github.com/worldiety/bacnet/common/netprim"
)

const (
	// DefaultMaxDatagramSize is a conservative IPv4 UDP payload budget.
	DefaultMaxDatagramSize = 1476
)

// DatagramConn is the small UDP surface required by the BVLC transport.
//
// The concrete connection is expected to already be bound to the desired local
// UDP address/port before it is passed to NewTransport.
type DatagramConn interface {
	// ReadFromUDPAddrPort reads from the already-bound local socket and returns
	// the sender's remote address/port.
	ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error)
	// WriteToUDPAddrPort sends one datagram to the given remote address/port.
	WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (n int, err error)

	Close() error
}

type connection struct {
	listener *net.UDPConn
}

func (c *connection) ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	return c.listener.ReadFromUDPAddrPort(p)
}

func (c *connection) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (n int, err error) {
	return c.listener.WriteTo(p, net.UDPAddrFromAddrPort(addr))
}

func (c *connection) Close() error {
	return c.listener.Close()
}

func NewDatagramConn(addr netip.Addr) (DatagramConn, error) {
	network, err := udpNetworkForAddress(addr)
	if err != nil {
		log.Logger.Error("bip transport select udp network", "error", err, "addr", addr)
		return nil, err
	}

	udpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, netprim.IpDefaultUdpPort))

	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		log.Logger.Error("bip transport listen udp", "error", err, "network", network, "addr", udpAddr)
		return nil, fmt.Errorf("failed to listen on %v: %w", udpAddr, err)
	}

	return ptr(connection{
		listener: conn,
	}), nil
}

func udpNetworkForAddress(addr netip.Addr) (string, error) {
	if !addr.IsValid() {
		return "", errors.NewValidationError("ip address", addr, errors.ErrInvalidIPAddress)
	}
	if addr.Is4() {
		return "udp4", nil
	}
	if addr.Is6() {
		return "udp6", nil
	}
	return "", errors.NewValidationError("ip address", addr, errors.ErrInvalidIPAddress)
}

func bvlcTypeForAddress(addr netip.Addr) (BVLCType, error) {
	if !addr.IsValid() {
		return 0, errors.NewValidationError("ip address", addr, errors.ErrInvalidIPAddress)
	}
	if addr.Is4() {
		return BVLCTypeBACnetIP, nil
	}
	if addr.Is6() {
		return BVLCTypeBACnetIP6, nil
	}
	return 0, errors.NewValidationError("ip address", addr, errors.ErrInvalidIPAddress)
}

// Transport sends and receives BVLC frames via UDP-like datagrams.
type Transport struct {
	conn            DatagramConn
	maxDatagramSize int
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

// NewTransport validates and constructs a BVLC transport.
func NewTransport(conn DatagramConn, maxDatagramSize int) (*Transport, error) {
	if conn == nil {
		return nil, ErrNilDatagramConn
	}
	if maxDatagramSize < BVLCHeaderLen {
		return nil, errors.NewValidationError("max datagram size", maxDatagramSize, ErrInvalidLength)
	}

	return &Transport{conn: conn, maxDatagramSize: maxDatagramSize}, nil
}

// ReceiveFrame reads one datagram and decodes it as BVLC frame.
//
// The returned netip.AddrPort is the remote sender address/port.
func (t *Transport) ReceiveFrame() (Frame, netip.AddrPort, error) {
	buf := make([]byte, t.maxDatagramSize)
	n, addr, err := t.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		log.Logger.Error("bip transport read datagram", "error", err)
		return Frame{}, netip.AddrPort{}, fmt.Errorf("%w: %v", ErrReadFailure, err)
	}

	frame, err := DecodeFrame(buf[:n])
	if err != nil {
		log.Logger.Error("bip transport decode frame", "error", err, "bytes", n)
		return Frame{}, netip.AddrPort{}, err
	}
	return frame, addr, nil
}

// SendFrame encodes and writes one BVLC frame datagram.
func (t *Transport) SendFrame(addr netip.AddrPort, frame Frame) error {
	raw, err := frame.Encode()
	if err != nil {
		log.Logger.Error("bip transport encode frame", "error", err, "dst", addr)
		return err
	}
	if len(raw) > t.maxDatagramSize {
		return errors.NewValidationError("datagram length", len(raw), ErrDatagramTooLarge)
	}

	if _, err := t.conn.WriteToUDPAddrPort(raw, addr); err != nil {
		log.Logger.Error("bip transport write datagram", "error", err, "dst", addr, "bytes", len(raw))
		return fmt.Errorf("%w: %v", ErrWriteFailure, err)
	}
	return nil
}
