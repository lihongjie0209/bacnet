package bacnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/bip"
	"github.com/worldiety/bacnet/common/log"
)

// ClientRuntimeConfig configures the high-level BACnet/IP client runtime.
//
// It combines transport, ASE, and typed APDU client settings into one place so
// callers can bootstrap an end-to-end client workflow with a single constructor.
type ClientRuntimeConfig struct {
	// MaxDatagramSize bounds the UDP datagram size used by the BVLC transport.
	// Zero defaults to DefaultMaxDatagramSize.
	MaxDatagramSize int

	// ASE contains APDU ASE transaction and timeout settings.
	ASE apdu.ASEConfig

	// Client contains typed APDU client defaults.
	Client apdu.ClientConfig
}

func DefaultClientRuntimeConfig() ClientRuntimeConfig {
	return ClientRuntimeConfig{
		MaxDatagramSize: bip.DefaultMaxDatagramSize,
		ASE:             apdu.DefaultASEConfig(),
		Client:          apdu.DefaultClientConfig(),
	}
}

// ClientRuntime wires DatagramConn -> Transport -> Stack -> ASE -> typed Client.
//
// Run starts the inbound receive loop. Close stops the ASE and transport.
type ClientRuntime struct {
	transport *bip.Transport
	stack     *bip.Stack
	ase       apdu.ASE
	client    apdu.Client
}

// NewClientRuntime creates a client runtime bound to localAddr.
func NewClientRuntime(localAddr netip.Addr, cfg ClientRuntimeConfig) (*ClientRuntime, error) {
	conn, err := bip.NewDatagramConn(localAddr)
	if err != nil {
		log.Logger.Error("bip client runtime create datagram conn", "error", err, "addr", localAddr)
		return nil, err
	}

	runtime, err := NewClientRuntimeWithConn(conn, cfg)
	if err != nil {
		log.Logger.Error("bip client runtime build with conn", "error", err)
		_ = conn.Close()
		return nil, err
	}

	return runtime, nil
}

// NewClientRuntimeWithConn creates a client runtime from an existing DatagramConn.
//
// This is useful for tests and advanced integrations that provide custom network
// adapters. conn must not be nil.
func NewClientRuntimeWithConn(conn bip.DatagramConn, cfg ClientRuntimeConfig) (*ClientRuntime, error) {
	if conn == nil {
		return nil, bip.ErrNilDatagramConn
	}

	if cfg.MaxDatagramSize == 0 {
		cfg.MaxDatagramSize = bip.DefaultMaxDatagramSize
	}

	transport, err := bip.NewTransport(conn, cfg.MaxDatagramSize)
	if err != nil {
		log.Logger.Error("bip client runtime create transport", "error", err)
		return nil, err
	}

	stack, err := bip.NewStack(transport)
	if err != nil {
		log.Logger.Error("bip client runtime create stack", "error", err)
		return nil, err
	}

	ase, err := apdu.NewASE(cfg.ASE, stack)
	if err != nil {
		log.Logger.Error("bip client runtime create ase", "error", err)
		return nil, err
	}

	client, err := apdu.NewClient(ase, cfg.Client)
	if err != nil {
		log.Logger.Error("bip client runtime create client", "error", err)
		_ = ase.Close()
		return nil, err
	}

	return &ClientRuntime{transport: transport, stack: stack, ase: ase, client: client}, nil
}

// Client returns the typed APDU client facade.
func (r *ClientRuntime) Client() apdu.Client {
	return r.client
}

// ASE returns the underlying APDU application service element.
func (r *ClientRuntime) ASE() apdu.ASE {
	return r.ase
}

// RegisterForeignDevice registers this runtime's existing UDP socket with a
// remote IPv4 BBMD and validates its correlated BVLC Result response. Run must
// be active so the shared receive loop can dispatch the response.
func (r *ClientRuntime) RegisterForeignDevice(ctx context.Context, bbmd netip.AddrPort, ttl bip.TTL) error {
	if r == nil || r.stack == nil {
		return errors.New("BACnet client runtime is unavailable")
	}
	if !bbmd.IsValid() || !bbmd.Addr().Is4() || bbmd.Port() == 0 {
		return fmt.Errorf("invalid BBMD address %s", bbmd)
	}
	request, err := bip.NewRegisterForeignDevice(ttl)
	if err != nil {
		return err
	}
	raw, err := request.Encode()
	if err != nil {
		return err
	}
	frame, err := bip.DecodeFrame(raw)
	if err != nil {
		return err
	}
	response, err := r.stack.RequestBVLC(ctx, bbmd, frame, bip.FunctionResult)
	if err != nil {
		return err
	}
	responseRaw, err := response.Encode()
	if err != nil {
		return err
	}
	var result bip.BVLCResult
	if err = result.Decode(responseRaw); err != nil {
		return err
	}
	if result.ResultCode() != bip.ResultCodeSuccessfulCompletion {
		return fmt.Errorf("%w: %v", bip.ErrRegistrationRejected, result.ResultCode())
	}
	return nil
}

// Run starts the inbound receive loop and dispatches inbound frames to the ASE.
func (r *ClientRuntime) Run(ctx context.Context) error {
	return r.stack.Run(ctx, r.ase)
}

// Close shuts down ASE state and closes the underlying datagram transport.
func (r *ClientRuntime) Close() error {
	if r == nil {
		return nil
	}

	var closeErr error

	if r.ase != nil {
		if err := r.ase.Close(); err != nil {
			closeErr = err
		}
	}

	if r.transport != nil {
		if err := r.transport.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}

	return closeErr
}
