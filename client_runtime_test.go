package bacnet

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/bip"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	"github.com/worldiety/bacnet/npdu"
)

type queuedResponse struct {
	data []byte
	src  netip.AddrPort
}

type runtimeLoopbackConn struct {
	mu sync.Mutex

	closed    bool
	responses chan queuedResponse
	written   []struct {
		data []byte
		addr netip.AddrPort
	}
	writeHook func(data []byte, addr netip.AddrPort)
}

func newRuntimeLoopbackConn() *runtimeLoopbackConn {
	return &runtimeLoopbackConn{responses: make(chan queuedResponse, 8)}
}

func (c *runtimeLoopbackConn) ReadFromUDPAddrPort(buf []byte) (int, netip.AddrPort, error) {
	for {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, netip.AddrPort{}, bip.ErrReadFailure
		}

		select {
		case r := <-c.responses:
			n := copy(buf, r.data)
			return n, r.src, nil
		case <-time.After(time.Millisecond):
		}
	}
}

func (c *runtimeLoopbackConn) WriteToUDPAddrPort(data []byte, addr netip.AddrPort) (int, error) {
	copied := make([]byte, len(data))
	copy(copied, data)

	c.mu.Lock()
	c.written = append(c.written, struct {
		data []byte
		addr netip.AddrPort
	}{data: copied, addr: addr})
	hook := c.writeHook
	c.mu.Unlock()

	if hook != nil {
		hook(copied, addr)
	}

	return len(data), nil
}

func (c *runtimeLoopbackConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *runtimeLoopbackConn) enqueueFrame(frame []byte, src netip.AddrPort) {
	c.responses <- queuedResponse{data: frame, src: src}
}

func TestNewClientRuntimeWithConn(t *testing.T) {
	aseCfg := apdu.ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}
	tests := []struct {
		name    string
		conn    bip.DatagramConn
		cfg     ClientRuntimeConfig
		wantErr error
	}{
		{name: "nil conn", conn: nil, cfg: ClientRuntimeConfig{ASE: aseCfg}, wantErr: bip.ErrNilDatagramConn},
		{name: "invalid ase config", conn: newRuntimeLoopbackConn(), cfg: ClientRuntimeConfig{}, wantErr: apdu.ErrInvalidASEConfig},
		{name: "valid defaults", conn: newRuntimeLoopbackConn(), cfg: ClientRuntimeConfig{ASE: aseCfg}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, err := NewClientRuntimeWithConn(tt.conn, tt.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewClientRuntimeWithConn error = %v, want %v", err, tt.wantErr)
			}
			if err == nil {
				if runtime.Client() == nil {
					t.Fatalf("Client() returned nil")
				}
				if closeErr := runtime.Close(); closeErr != nil {
					t.Fatalf("Close() error = %v", closeErr)
				}
			}
		})
	}
}

func TestClientRuntimeRegisterForeignDeviceUsesSharedReceiveLoop(t *testing.T) {
	conn := newRuntimeLoopbackConn()
	runtime, err := NewClientRuntimeWithConn(conn, ClientRuntimeConfig{ASE: apdu.ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	peer := netip.MustParseAddrPort("192.0.2.10:47808")
	conn.writeHook = func(data []byte, address netip.AddrPort) {
		var request bip.RegisterForeignDevice
		if decodeErr := request.Decode(data); decodeErr != nil {
			t.Errorf("decode registration: %v", decodeErr)
			return
		}
		if request.TTL() != 60 || address != peer {
			t.Errorf("registration ttl=%d address=%s", request.TTL(), address)
		}
		result, _ := bip.NewBVLCResult(bip.ResultCodeSuccessfulCompletion)
		response, _ := result.Encode()
		conn.enqueueFrame(response, address)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(runCtx) }()
	if err = runtime.RegisterForeignDevice(t.Context(), peer, 60); err != nil {
		t.Fatal(err)
	}
	cancelRun()
	_ = runtime.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestClientRuntimeRunWritePropertyRoundTrip(t *testing.T) {
	conn := newRuntimeLoopbackConn()
	runtime, err := NewClientRuntimeWithConn(conn, ClientRuntimeConfig{
		ASE: apdu.ASEConfig{InvokeTimeout: 200 * time.Millisecond, APDURetries: 0, MaxConcurrentInvokes: 4},
	})
	if err != nil {
		t.Fatalf("NewClientRuntimeWithConn returned error: %v", err)
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			t.Fatalf("Close returned error: %v", closeErr)
		}
	}()

	peer := netip.MustParseAddrPort("192.168.10.20:47808")
	conn.writeHook = func(data []byte, addr netip.AddrPort) {
		frame, err := bip.DecodeFrame(data)
		if err != nil {
			t.Fatalf("DecodeFrame(write) returned error: %v", err)
		}

		var requestNPDU npdu.NetworkLayerProtocolDataUnit
		if err := requestNPDU.Decode(frame.PayloadBytes()); err != nil {
			t.Fatalf("NPDU decode returned error: %v", err)
		}

		apduBytes := requestNPDU.APDUBytes()
		if len(apduBytes) < 4 {
			t.Fatalf("request APDU too short: %d", len(apduBytes))
		}

		invokeID := apduBytes[2]
		serviceChoice := apduBytes[3]
		ackAPDU := []byte{byte(apdu.PDUTypeSimpleACK << 4), invokeID, serviceChoice}

		ackNPDU, err := npdu.NewLocalAPDU(requestNPDU.Priority(), false, ackAPDU)
		if err != nil {
			t.Fatalf("NewLocalAPDU(ack) returned error: %v", err)
		}
		ackNPDUBytes, err := ackNPDU.Encode()
		if err != nil {
			t.Fatalf("NPDU encode returned error: %v", err)
		}

		ackFrame, err := bip.NewOriginalUnicastNpdu(bip.BVLCTypeBACnetIP, ackNPDUBytes)
		if err != nil {
			t.Fatalf("NewOriginalUnicastNpdu returned error: %v", err)
		}
		ackWire, err := ackFrame.Encode()
		if err != nil {
			t.Fatalf("OriginalUnicastNpdu.Encode returned error: %v", err)
		}

		conn.enqueueFrame(ackWire, addr)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(runCtx) }()

	dst, err := netprim.AddrPortToAddress(peer)
	if err != nil {
		t.Fatalf("AddrPortToAddress returned error: %v", err)
	}

	objID, err := types.NewObjectIdentifier(types.ObjectTypeAnalogValue, 1)
	if err != nil {
		t.Fatalf("NewObjectIdentifier returned error: %v", err)
	}

	writeReq := apdu.WritePropertyRequest{
		ObjectIdentifier:   objID,
		PropertyIdentifier: types.PropertyIdentifierPresentValue,
		PropertyValue:      []byte{0x44, 0x20, 0x00, 0x00},
	}

	if err := runtime.Client().WriteProperty(context.Background(), dst, writeReq); err != nil {
		t.Fatalf("WriteProperty returned error: %v", err)
	}

	conn.mu.Lock()
	writeCount := len(conn.written)
	conn.mu.Unlock()
	if writeCount == 0 {
		t.Fatalf("runtime did not write any datagram")
	}

	cancelRun()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not stop after cancel")
	}
}
