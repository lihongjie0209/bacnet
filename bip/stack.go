package bip

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/log"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/npdu"
)

// Stack bridges the BACnet/IP transport layer and the APDU service element (ASE).
//
// It implements apdu.NPDUTransport so it can be passed directly to apdu.NewASE,
// and it provides a Run method that pumps inbound UDP datagrams into the ASE.
//
// Typical usage:
//
//	conn, _ := bip.NewDatagramConn(localAddr)
//	transport, _ := bip.NewTransport(conn, bip.DefaultMaxDatagramSize)
//	stack, _ := bip.NewStack(transport)
//	ase, _ := apdu.NewASE(cfg, stack)
//	defer ase.Close()
//	go stack.Run(ctx, ase)
type Stack struct {
	transport        *Transport
	controlMu        sync.Mutex
	controlResponses chan controlResponse
}

type controlResponse struct {
	frame  Frame
	sender netip.AddrPort
}

// NewStack constructs a Stack around an existing Transport.
// transport must not be nil.
func NewStack(transport *Transport) (*Stack, error) {
	if transport == nil {
		return nil, ErrNilTransport
	}
	return &Stack{transport: transport, controlResponses: make(chan controlResponse, 16)}, nil
}

// RequestBVLC sends one BVLC control frame and waits for a response with the
// expected function from the same peer. Control requests are serialized so a
// Result frame can never be correlated to the wrong operation.
func (s *Stack) RequestBVLC(ctx context.Context, peer netip.AddrPort, request Frame, expected BVLCFunctionType) (Frame, error) {
	if !peer.IsValid() || !peer.Addr().Is4() || peer.Port() == 0 {
		return Frame{}, fmt.Errorf("invalid BACnet/IP control peer %s", peer)
	}
	if !expected.Valid() {
		return Frame{}, ErrInvalidFunction
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	for {
		select {
		case <-s.controlResponses:
		default:
			goto drained
		}
	}
drained:
	if err := s.transport.SendFrame(peer, request); err != nil {
		return Frame{}, err
	}
	for {
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		case response := <-s.controlResponses:
			if response.sender == peer && response.frame.Function == expected {
				return response.frame, nil
			}
		}
	}
}

// SendNPDU implements apdu.NPDUTransport.
//
// It encodes packet to wire bytes, wraps them in an Original-Unicast-NPDU BVLC
// frame, and sends the datagram to the UDP address derived from dst via
// AddressToAddrPort. dst must be a local-network BACnet/IP address (6-byte MAC).
func (s *Stack) SendNPDU(_ context.Context, dst netprim.Address, packet npdu.NetworkLayerProtocolDataUnit) error {
	npduBytes, err := packet.Encode()
	if err != nil {
		log.Logger.Error("bip stack encode npdu", "error", err, "dst_network", dst.Network)
		return fmt.Errorf("%w: encode npdu: %v", ErrWriteFailure, err)
	}

	frame, err := NewFrameWithType(BVLCTypeBACnetIP, FunctionOriginalUnicastNPDU, npduBytes)
	if err != nil {
		log.Logger.Error("bip stack build unicast frame", "error", err, "dst", dst)
		return fmt.Errorf("%w: build original-unicast-npdu frame: %v", ErrWriteFailure, err)
	}

	if err := s.transport.SendFrame(dst.AddrPort, frame); err != nil {
		log.Logger.Error("bip stack send frame", "error", err, "dst", dst.AddrPort)
		return fmt.Errorf("%w: %v", ErrWriteFailure, err)
	}
	return nil
}

// Run starts the inbound receive loop for the Stack, pumping each arriving BVLC
// frame into ase through OnInboundNPDU.
//
// The loop runs until ctx is cancelled or the underlying transport returns a
// permanent error. When ctx is cancelled, Run closes the transport to unblock
// any pending read and then returns ctx.Err().
//
// Frame-level errors (malformed NPDU, unrecognised BVLC function, etc.) are
// silently skipped so that a single bad datagram does not kill the loop.
//
// ase must not be nil.
func (s *Stack) Run(ctx context.Context, ase apdu.ASE) error {
	if ase == nil {
		return ErrNilASE
	}

	// Close the transport when the context is cancelled so that the blocking
	// ReceiveFrame call returns promptly.
	go func() {
		<-ctx.Done()
		_ = s.transport.Close()
	}()

	for {
		frame, senderAddr, err := s.transport.ReceiveFrame()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Logger.Error("bip stack receive frame", "error", err)
			return fmt.Errorf("%w: %v", ErrReadFailure, err)
		}

		_ = s.dispatchFrame(ctx, ase, frame, senderAddr)
	}
}

// dispatchFrame resolves the logical BACnet source address and NPDU bytes from
// an inbound BVLC frame and calls ase.OnInboundNPDU.
//
// Supported function types:
//   - FunctionOriginalUnicastNPDU   – sender is identified by senderAddr.
//   - FunctionOriginalBroadcastNPDU – sender is identified by senderAddr.
//   - FunctionForwardedNPDU         – sender is the originating device encoded
//     in the BVLC payload; the receiving BBMD's address (senderAddr) is ignored.
//
// All other function types are silently ignored.
func (s *Stack) dispatchFrame(ctx context.Context, ase apdu.ASE, frame Frame, senderAddr netip.AddrPort) error {
	var npduBytes []byte
	var src netprim.Address

	payload := frame.PayloadBytes()

	switch frame.Function {
	case FunctionOriginalUnicastNPDU, FunctionOriginalBroadcastNPDU:
		addr, err := netprim.AddrPortToAddress(senderAddr)
		if err != nil {
			log.Logger.Error("bip stack decode sender address", "error", err, "sender", senderAddr)
			return err
		}
		src = addr
		npduBytes = payload

	case FunctionForwardedNPDU:
		// The first 6 bytes of the payload are the originating device's B/IP address.
		if len(payload) <= 6 {
			log.Logger.Error("bip stack forwarded payload too short", "error", ErrReadFailure, "bytes", len(payload))
			return fmt.Errorf("forwarded-npdu payload too short: %d bytes", len(payload))
		}
		originAddr, err := decodeAddressPortIpV4(payload[:6])
		if err != nil {
			log.Logger.Error("bip stack decode forwarded origin", "error", err)
			return fmt.Errorf("decode forwarded-npdu origin address: %w", err)
		}
		addr, err := netprim.AddrPortToAddress(originAddr)
		if err != nil {
			log.Logger.Error("bip stack convert forwarded origin", "error", err, "origin", originAddr)
			return err
		}
		src = addr
		npduBytes = payload[6:]

	default:
		// Deliver BBMD control responses to the serialized control requester.
		// Unsolicited or excess responses are intentionally dropped.
		select {
		case s.controlResponses <- controlResponse{frame: frame, sender: senderAddr}:
		default:
		}
		return nil
	}

	var pkt npdu.NetworkLayerProtocolDataUnit
	if err := pkt.Decode(npduBytes); err != nil {
		log.Logger.Error("bip stack decode npdu", "error", err, "bytes", len(npduBytes))
		return fmt.Errorf("decode npdu: %w", err)
	}

	// If the NPDU carries a source specifier, the message originated on a remote
	// network (e.g. an MS/TP node behind a router). Preserve the originating
	// network number and MAC so the device can be addressed for later requests;
	// AddrPort remains the router's B/IP address (where replies are sent).
	if pkt.HasSourceSpecifier() {
		if snet := pkt.SNET(); snet != nil {
			src.Network = snet.ToBacnetNetworkNumber()
			src.MAC = pkt.SADR()
		}
	}

	return ase.OnInboundNPDU(ctx, src, pkt)
}
