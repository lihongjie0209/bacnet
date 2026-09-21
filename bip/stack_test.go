package bip

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/npdu"
)

// ---- helpers ------------------------------------------------------------------

// pipeConn is a simple in-memory DatagramConn: writes are captured, reads are
// served from a pre-loaded queue.
type pipeConn struct {
	queue    []queuedResponse
	readIdx  int
	writeErr error

	mu     sync.Mutex
	closed bool

	written []struct {
		data []byte
		addr netip.AddrPort
	}
}

func (p *pipeConn) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *pipeConn) ReadFromUDPAddrPort(buf []byte) (int, netip.AddrPort, error) {
	if p.isClosed() {
		return 0, netip.AddrPort{}, ErrReadFailure
	}
	if p.readIdx >= len(p.queue) {
		// Block until closed (simulates an idle socket).
		for !p.isClosed() {
			time.Sleep(time.Millisecond)
		}
		return 0, netip.AddrPort{}, ErrReadFailure
	}
	r := p.queue[p.readIdx]
	p.readIdx++
	n := copy(buf, r.data)
	return n, r.src, nil
}

func (p *pipeConn) WriteToUDPAddrPort(data []byte, addr netip.AddrPort) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.writeErr != nil {
		return 0, p.writeErr
	}
	d := make([]byte, len(data))
	copy(d, data)
	p.written = append(p.written, struct {
		data []byte
		addr netip.AddrPort
	}{data: d, addr: addr})
	return len(data), nil
}

func (p *pipeConn) writeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.written)
}

func (p *pipeConn) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

func mustStack(t *testing.T, conn DatagramConn) *Stack {
	t.Helper()
	tr, err := NewTransport(conn, DefaultMaxDatagramSize)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	s, err := NewStack(tr)
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	return s
}

// minLocalNPDU builds the shortest valid local APDU NPDU (2 header bytes + payload).
func minLocalNPDU(t *testing.T, apduBytes []byte) []byte {
	t.Helper()
	pkt, err := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, apduBytes)
	if err != nil {
		t.Fatalf("NewLocalAPDU: %v", err)
	}
	b, err := pkt.Encode()
	if err != nil {
		t.Fatalf("NPDU.Encode: %v", err)
	}
	return b
}

// buildOriginalUnicastFrame encodes a complete Original-Unicast-NPDU BVLC frame
// carrying npduBytes that can be fed to Transport.ReceiveFrame.
func buildOriginalUnicastFrame(t *testing.T, npduBytes []byte) []byte {
	t.Helper()
	msg, err := NewOriginalUnicastNpdu(BVLCTypeBACnetIP, npduBytes)
	if err != nil {
		t.Fatalf("NewOriginalUnicastNpdu: %v", err)
	}
	raw, err := msg.Encode()
	if err != nil {
		t.Fatalf("OriginalUnicastNpdu.Encode: %v", err)
	}
	return raw
}

// buildOriginalBroadcastFrame builds a broadcast BVLC frame.
func buildOriginalBroadcastFrame(t *testing.T, npduBytes []byte) []byte {
	t.Helper()
	msg, err := NewOriginalBroadcastNpdu(BVLCTypeBACnetIP, npduBytes)
	if err != nil {
		t.Fatalf("NewOriginalBroadcastNpdu: %v", err)
	}
	raw, err := msg.Encode()
	if err != nil {
		t.Fatalf("OriginalBroadcastNpdu.Encode: %v", err)
	}
	return raw
}

// buildForwardedNpduFrame builds a Forwarded-NPDU BVLC frame.
func buildForwardedNpduFrame(t *testing.T, originAddr netip.AddrPort, npduBytes []byte) []byte {
	t.Helper()
	msg, err := NewForwardedNpdu(originAddr, npduBytes)
	if err != nil {
		t.Fatalf("NewForwardedNpdu: %v", err)
	}
	raw, err := msg.Encode()
	if err != nil {
		t.Fatalf("ForwardedNpdu.Encode: %v", err)
	}
	return raw
}

// ---- testASE ------------------------------------------------------------------

// testASE captures calls to OnInboundNPDU.
type testASE struct {
	calls []inboundCall
}

type inboundCall struct {
	src netprim.Address
	pkt npdu.NetworkLayerProtocolDataUnit
}

func (a *testASE) RegisterConfirmed(_ apdu.ServiceChoice, _ apdu.ConfirmedHandler) error {
	return nil
}
func (a *testASE) RegisterUnconfirmed(_ apdu.ServiceChoice, _ apdu.UnconfirmedHandler) error {
	return nil
}
func (a *testASE) BeginConfirmedServiceRequest(_ context.Context, _ apdu.ConfirmedRequestICI) (apdu.ConfirmICI, error) {
	return apdu.ConfirmICI{}, nil
}
func (a *testASE) SendUnconfirmed(_ context.Context, _ apdu.UnconfirmedRequestICI) error {
	return nil
}
func (a *testASE) OnInboundNPDU(_ context.Context, src netprim.Address, pkt npdu.NetworkLayerProtocolDataUnit) error {
	a.calls = append(a.calls, inboundCall{src: src, pkt: pkt})
	return nil
}
func (a *testASE) Close() error { return nil }

// ---- NewStack tests -----------------------------------------------------------

func TestNewStack(t *testing.T) {
	conn := &pipeConn{}
	tr, _ := NewTransport(conn, DefaultMaxDatagramSize)

	tests := []struct {
		name      string
		transport *Transport
		wantErr   error
	}{
		{name: "valid", transport: tr},
		{name: "nil transport", transport: nil, wantErr: ErrNilTransport},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStack(tt.transport)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// ---- SendNPDU tests -----------------------------------------------------------

func TestStackSendNPDUEncoding(t *testing.T) {
	conn := &pipeConn{}
	s := mustStack(t, conn)

	apduBytes := []byte{0x10, 0x08} // unconfirmed-request, WhoIs
	pkt, err := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, apduBytes)
	if err != nil {
		t.Fatalf("NewLocalAPDU: %v", err)
	}

	// A BACnet/IP peer at 192.168.1.20:47808.
	dstAddrPort := netip.MustParseAddrPort("192.168.1.20:47808")
	dst, err := netprim.AddrPortToAddress(dstAddrPort)
	if err != nil {
		t.Fatalf("AddrPortToAddress: %v", err)
	}

	if err := s.SendNPDU(context.Background(), dst, *pkt); err != nil {
		t.Fatalf("SendNPDU: %v", err)
	}

	if len(conn.written) != 1 {
		t.Fatalf("written datagrams = %d, want 1", len(conn.written))
	}

	// Verify the UDP destination.
	if conn.written[0].addr != dstAddrPort {
		t.Errorf("UDP dst = %v, want %v", conn.written[0].addr, dstAddrPort)
	}

	// Verify the BVLC function type byte (byte 1 of the frame).
	wire := conn.written[0].data
	if len(wire) < BVLCHeaderLen {
		t.Fatalf("wire too short: %d bytes", len(wire))
	}
	if wire[0] != byte(BVLCTypeBACnetIP) {
		t.Errorf("BVLC type = 0x%02x, want 0x%02x", wire[0], BVLCTypeBACnetIP)
	}
	if wire[1] != byte(FunctionOriginalUnicastNPDU) {
		t.Errorf("BVLC function = 0x%02x, want 0x%02x", wire[1], FunctionOriginalUnicastNPDU)
	}

	// Verify BVLC length field matches actual wire length.
	declaredLen := int(binary.BigEndian.Uint16(wire[2:4]))
	if declaredLen != len(wire) {
		t.Errorf("declared length %d != actual %d", declaredLen, len(wire))
	}
}

func TestStackSendNPDUWriteError(t *testing.T) {
	conn := &pipeConn{writeErr: ErrWriteFailure}
	s := mustStack(t, conn)

	pkt, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, []byte{0x01})
	dst, _ := netprim.AddrPortToAddress(netip.MustParseAddrPort("1.2.3.4:47808"))

	err := s.SendNPDU(context.Background(), dst, *pkt)
	if !errors.Is(err, ErrWriteFailure) {
		t.Fatalf("err = %v, want %v", err, ErrWriteFailure)
	}
}

func TestStackRequestBVLCCorrelatesPeerAndFunction(t *testing.T) {
	conn := &pipeConn{}
	stack := mustStack(t, conn)
	peer := netip.MustParseAddrPort("192.0.2.10:47808")
	request, err := NewFrameWithType(BVLCTypeBACnetIP, FunctionRegisterForeignDevice, []byte{0, 60})
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		frame Frame
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		frame, requestErr := stack.RequestBVLC(t.Context(), peer, request, FunctionResult)
		done <- outcome{frame: frame, err: requestErr}
	}()
	deadline := time.Now().Add(time.Second)
	for conn.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.writeCount() != 1 {
		t.Fatal("control request was not sent")
	}
	result, _ := NewBVLCResult(ResultCodeSuccessfulCompletion)
	raw, _ := result.Encode()
	response, _ := DecodeFrame(raw)
	if err = stack.dispatchFrame(t.Context(), &testASE{}, response, netip.MustParseAddrPort("192.0.2.11:47808")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("accepted response from wrong peer")
	case <-time.After(10 * time.Millisecond):
	}
	if err = stack.dispatchFrame(t.Context(), &testASE{}, response, peer); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-done:
		if outcome.err != nil || outcome.frame.Function != FunctionResult {
			t.Fatalf("outcome=%#v", outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for correlated control response")
	}
}

func TestStackRequestBVLCHonorsCancellation(t *testing.T) {
	stack := mustStack(t, &pipeConn{})
	request, _ := NewFrameWithType(BVLCTypeBACnetIP, FunctionReadForeignDeviceTable, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := stack.RequestBVLC(ctx, netip.MustParseAddrPort("192.0.2.10:47808"), request, FunctionReadForeignDeviceTableAck)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

// ---- Run dispatch tests -------------------------------------------------------

func TestStackRunNilASE(t *testing.T) {
	conn := &pipeConn{}
	s := mustStack(t, conn)
	err := s.Run(context.Background(), nil)
	if !errors.Is(err, ErrNilASE) {
		t.Fatalf("err = %v, want %v", err, ErrNilASE)
	}
}

func TestStackRunContextCancel(t *testing.T) {
	conn := &pipeConn{} // no queued frames; will block until closed
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestStackRunDispatchesUnicastFrame(t *testing.T) {
	sender := netip.MustParseAddrPort("192.168.1.5:47808")
	npduBytes := minLocalNPDU(t, []byte{0x10, 0x08})
	wire := buildOriginalUnicastFrame(t, npduBytes)

	conn := &pipeConn{queue: []queuedResponse{{data: wire, src: sender}}}
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	// Allow the frame to be dispatched, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(ase.calls) != 1 {
		t.Fatalf("OnInboundNPDU calls = %d, want 1", len(ase.calls))
	}

	wantSrc, _ := netprim.AddrPortToAddress(sender)
	if !ase.calls[0].src.Equal(wantSrc) {
		t.Errorf("src = %v, want %v", ase.calls[0].src, wantSrc)
	}
}

func TestStackRunDispatchesBroadcastFrame(t *testing.T) {
	sender := netip.MustParseAddrPort("10.0.0.3:47808")
	npduBytes := minLocalNPDU(t, []byte{0x10, 0x08})
	wire := buildOriginalBroadcastFrame(t, npduBytes)

	conn := &pipeConn{queue: []queuedResponse{{data: wire, src: sender}}}
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(ase.calls) != 1 {
		t.Fatalf("OnInboundNPDU calls = %d, want 1", len(ase.calls))
	}

	wantSrc, _ := netprim.AddrPortToAddress(sender)
	if !ase.calls[0].src.Equal(wantSrc) {
		t.Errorf("src = %v, want %v", ase.calls[0].src, wantSrc)
	}
}

func TestStackRunDispatchesForwardedFrame(t *testing.T) {
	bbmd := netip.MustParseAddrPort("10.0.0.1:47808")
	originator := netip.MustParseAddrPort("172.16.0.50:47808")
	npduBytes := minLocalNPDU(t, []byte{0x10, 0x08})
	wire := buildForwardedNpduFrame(t, originator, npduBytes)

	conn := &pipeConn{queue: []queuedResponse{{data: wire, src: bbmd}}}
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(ase.calls) != 1 {
		t.Fatalf("OnInboundNPDU calls = %d, want 1", len(ase.calls))
	}

	// Source must be the originator, NOT the BBMD.
	wantSrc, _ := netprim.AddrPortToAddress(originator)
	if !ase.calls[0].src.Equal(wantSrc) {
		t.Errorf("src = %v, want originator %v", ase.calls[0].src, wantSrc)
	}
}

func TestStackRunSkipsNonAPDUFrames(t *testing.T) {
	sender := netip.MustParseAddrPort("10.0.0.1:47808")
	// A ReadBDT request is a BBMD control frame, not an APDU-containing frame.
	rbt := NewReadBroadcastDistributionTable()
	wire, _ := rbt.Encode()

	conn := &pipeConn{queue: []queuedResponse{{data: wire, src: sender}}}
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(ase.calls) != 0 {
		t.Fatalf("OnInboundNPDU calls = %d, want 0 (non-APDU frame should be skipped)", len(ase.calls))
	}
}

// minSourcedNPDU builds a routed I-Am NPDU carrying a source specifier
// (SNET/SADR), as a router emits for a message originating on a remote network.
func minSourcedNPDU(t *testing.T, snet uint16, sadr []byte, apduBytes []byte) []byte {
	t.Helper()
	pkt, err := npdu.NewSourcedAPDU(
		npdu.OriginalSourceNetworkNumber(snet),
		npdu.OriginalSourceMacLayerAddress(sadr),
		netprim.NetworkPriorityNormal,
		false,
		apduBytes,
	)
	if err != nil {
		t.Fatalf("NewSourcedAPDU: %v", err)
	}
	b, err := pkt.Encode()
	if err != nil {
		t.Fatalf("NPDU.Encode: %v", err)
	}
	return b
}

// TestStackRunExtractsRoutedSource verifies that a message arriving with an
// NPDU source specifier (a device on a remote network behind a router) carries
// its originating network and MAC into the src Address, while AddrPort remains
// the router's B/IP address (the UDP sender).
func TestStackRunExtractsRoutedSource(t *testing.T) {
	router := netip.MustParseAddrPort("10.6.6.110:47808")
	// I-Am from an MS/TP node: network 4, MAC 0x22.
	npduBytes := minSourcedNPDU(t, 4, []byte{0x22}, []byte{0x10, 0x00})
	wire := buildOriginalUnicastFrame(t, npduBytes)

	conn := &pipeConn{queue: []queuedResponse{{data: wire, src: router}}}
	s := mustStack(t, conn)
	ase := &testASE{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ase) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(ase.calls) != 1 {
		t.Fatalf("OnInboundNPDU calls = %d, want 1", len(ase.calls))
	}
	src := ase.calls[0].src
	if src.Network != 4 {
		t.Errorf("src.Network = %d, want 4 (remote network)", src.Network)
	}
	if len(src.MAC) != 1 || src.MAC[0] != 0x22 {
		t.Errorf("src.MAC = % x, want 22", src.MAC)
	}
	if src.AddrPort != router {
		t.Errorf("src.AddrPort = %v, want router %v", src.AddrPort, router)
	}
	if !src.IsRouted() {
		t.Error("src.IsRouted() = false, want true")
	}
}
