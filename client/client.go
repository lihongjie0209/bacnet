// Package client provides an ergonomic, high-level facade over the low-level
// BACnet/IP building blocks in this module (apdu, bip, encoding, netprim).
//
// It hides the mechanical details of running a client runtime, addressing
// devices, encoding/decoding property values, discovering devices across
// multiple network interfaces, and resolving BACnet device IDs to transport
// addresses. It is designed for real-world tooling and commissioning workflows
// (the bacnetf CLI is built on top of it).
//
// Typical use:
//
//	c, err := client.New(client.Config{})
//	if err != nil { ... }
//	defer c.Close()
//
//	devices, _ := c.Discover(ctx)
//	v, _ := c.ReadProperty(ctx, client.TargetID(5123),
//	    client.Object{Type: types.ObjectTypeAnalogInput, Instance: 250},
//	    types.PropertyIdentifierPresentValue)
//	fmt.Println(v.Display(types.PropertyIdentifierPresentValue))
//
// The package is UI-agnostic: it returns structured data and errors and prints
// nothing itself.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/worldiety/bacnet"
	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/bip"
	baclog "github.com/worldiety/bacnet/common/log"
)

// Default timing values used when a Config field is left zero.
const (
	defaultTimeout       = 10 * time.Second
	defaultRetries       = 3
	defaultResolveWindow = 2 * time.Second
	defaultWindow        = 5 * time.Second
)

// Config configures a Client. The zero value is valid and yields a client bound
// to all interfaces with sensible defaults and quiet logging.
type Config struct {
	// Interface is the local IPv4 address to bind. The zero value binds to all
	// interfaces (0.0.0.0), which is recommended for discovery so that
	// broadcast I-Am replies are received.
	Interface netip.Addr

	// Broadcast overrides the Who-Is broadcast address. The zero value
	// auto-detects the directed broadcast of every broadcast-capable interface.
	Broadcast netip.Addr

	// Timeout is the per-request invoke timeout. Zero uses 10s.
	Timeout time.Duration

	// Retries is the number of APDU retransmission attempts. Negative uses 3.
	Retries int

	// Pacing is an optional delay inserted between sequential requests in
	// batch operations (e.g. object-list enumeration) to be gentle on slow
	// MS/TP segments. Zero disables pacing.
	Pacing time.Duration

	// ResolveWindow is how long to wait for an I-Am when resolving a device ID
	// to an address. Zero uses 2s.
	ResolveWindow time.Duration

	// ForeignDevice registers the client's existing BACnet/IP socket with a
	// remote BBMD before New returns and renews it before its TTL expires.
	ForeignDevice *ForeignDeviceConfig

	// Logger, when non-nil, installs this logger as the library's global
	// logger. When nil, library logging is discarded so the client is quiet by
	// default. (The underlying library uses a single global logger.)
	Logger *slog.Logger
}

type ForeignDeviceConfig struct {
	BBMD        netip.AddrPort
	TTL         time.Duration
	RenewBefore time.Duration
}

func (c Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c Config) retries() int {
	if c.Retries < 0 {
		return defaultRetries
	}
	return c.Retries
}

func (c Config) resolveWindow() time.Duration {
	if c.ResolveWindow > 0 {
		return c.ResolveWindow
	}
	return defaultResolveWindow
}

// Client is a live, ergonomic BACnet/IP client. It is safe for use by a single
// goroutine at a time for a given request; discovery operations may run
// concurrently. Create one with New and release it with Close.
type Client struct {
	cfg         Config
	rt          *bacnet.ClientRuntime
	externalASE apdu.ASE
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
	renewalErr  error
	closeOnce   sync.Once
	closeErr    error

	// apduClientOverride, when non-nil, supplies the APDU client instead of the
	// runtime's. It exists so tests can inject a fake transport without a live
	// socket; production code leaves it nil.
	apduClientOverride apdu.Client
}

// NewWithTransport creates a high-level BACnet client over a caller-owned NPDU
// transport. The returned ASE receives inbound NPDUs through OnInboundNPDU.
// Closing the client closes the ASE but does not close the caller's transport.
func NewWithTransport(cfg Config, transport apdu.NPDUTransport, maxAPDU apdu.MaxApduLengthAccepted) (*Client, apdu.ASE, error) {
	if transport == nil {
		return nil, nil, errors.New("NPDU transport is required")
	}
	if cfg.ForeignDevice != nil {
		return nil, nil, errors.New("foreign-device registration requires BACnet/IP")
	}
	if cfg.Logger != nil {
		baclog.Logger = cfg.Logger
	} else {
		baclog.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	aseConfig := apdu.DefaultASEConfig()
	aseConfig.InvokeTimeout = cfg.timeout()
	aseConfig.APDURetries = uint8(cfg.retries())
	if maxAPDU != 0 {
		aseConfig.MaxAPDUSizeAccepted = maxAPDU
	}
	ase, err := apdu.NewASE(aseConfig, transport)
	if err != nil {
		return nil, nil, fmt.Errorf("create ASE: %w", err)
	}
	clientConfig := apdu.DefaultClientConfig()
	if maxAPDU != 0 {
		clientConfig.MaxAPDULengthAccepted = maxAPDU
	}
	typed, err := apdu.NewClient(ase, clientConfig)
	if err != nil {
		_ = ase.Close()
		return nil, nil, fmt.Errorf("create APDU client: %w", err)
	}
	client := &Client{cfg: cfg, externalASE: ase, apduClientOverride: typed}
	return client, ase, nil
}

// New creates and starts a BACnet client runtime from cfg. The caller must call
// Close when finished.
func New(cfg Config) (*Client, error) {
	if cfg.Logger != nil {
		baclog.Logger = cfg.Logger
	} else {
		// Quiet by default: the library uses a single global logger, and a
		// downstream consumer should not get unsolicited output.
		baclog.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	bindAddr := netip.AddrFrom4([4]byte{0, 0, 0, 0})
	if cfg.Interface.IsValid() {
		if !cfg.Interface.Is4() {
			return nil, fmt.Errorf("interface %s must be an IPv4 address", cfg.Interface)
		}
		bindAddr = cfg.Interface
	}

	rtCfg := bacnet.DefaultClientRuntimeConfig()
	rtCfg.ASE.InvokeTimeout = cfg.timeout()
	rtCfg.ASE.APDURetries = uint8(cfg.retries())
	// MaxConcurrentInvokes must stay > 0; DefaultClientRuntimeConfig sets it.

	rt, err := bacnet.NewClientRuntime(bindAddr, rtCfg)
	if err != nil {
		return nil, fmt.Errorf("create client runtime: %w", err)
	}

	foreign, err := validateForeignDeviceConfig(cfg.ForeignDevice)
	if err != nil {
		_ = rt.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{cfg: cfg, rt: rt, cancel: cancel}
	client.wg.Add(1)
	go func() {
		defer client.wg.Done()
		_ = rt.Run(ctx)
	}()
	if foreign != nil {
		registerCtx, registerCancel := context.WithTimeout(ctx, cfg.timeout())
		err = rt.RegisterForeignDevice(registerCtx, foreign.BBMD, foreign.ttl)
		registerCancel()
		if err != nil {
			cancel()
			_ = rt.Close()
			client.wg.Wait()
			return nil, fmt.Errorf("register BACnet foreign device: %w", err)
		}
		client.wg.Add(1)
		go client.renewForeignDevice(ctx, foreign)
	}
	return client, nil
}

type resolvedForeignDeviceConfig struct {
	BBMD       netip.AddrPort
	ttl        bip.TTL
	renewEvery time.Duration
}

func validateForeignDeviceConfig(config *ForeignDeviceConfig) (*resolvedForeignDeviceConfig, error) {
	if config == nil {
		return nil, nil
	}
	if !config.BBMD.IsValid() || !config.BBMD.Addr().Is4() || config.BBMD.Port() == 0 {
		return nil, errors.New("foreign device BBMD must be an IPv4 host:port")
	}
	if config.TTL < time.Second || config.TTL > 65535*time.Second || config.TTL%time.Second != 0 {
		return nil, errors.New("foreign device TTL must be 1..65535 whole seconds")
	}
	if config.RenewBefore <= 0 || config.RenewBefore >= config.TTL {
		return nil, errors.New("foreign device renewBefore must be positive and less than TTL")
	}
	return &resolvedForeignDeviceConfig{BBMD: config.BBMD, ttl: bip.TTL(config.TTL / time.Second), renewEvery: config.TTL - config.RenewBefore}, nil
}

func (c *Client) renewForeignDevice(ctx context.Context, config *resolvedForeignDeviceConfig) {
	defer c.wg.Done()
	timer := time.NewTimer(config.renewEvery)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			registerCtx, cancel := context.WithTimeout(ctx, c.cfg.timeout())
			err := c.rt.RegisterForeignDevice(registerCtx, config.BBMD, config.ttl)
			cancel()
			if err != nil {
				c.mu.Lock()
				c.renewalErr = fmt.Errorf("renew BACnet foreign device: %w", err)
				c.mu.Unlock()
				_ = c.rt.Close()
				return
			}
			timer.Reset(config.renewEvery)
		}
	}
}

// Health reports a terminal foreign-device renewal failure, if any.
func (c *Client) Health() error {
	if c == nil {
		return errors.New("BACnet client is nil")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.renewalErr
}

// Close stops the background receive loop and releases the UDP socket.
//
// Closing the transport while the receive loop is blocked on a read causes the
// library to log a benign "use of closed network connection" error. Unless a
// custom logger was configured, the library logger is already discarding
// output, so this shutdown artifact is not shown.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.rt != nil {
			c.closeErr = c.rt.Close()
		}
		if c.externalASE != nil {
			c.closeErr = errors.Join(c.closeErr, c.externalASE.Close())
		}
		c.wg.Wait()
	})
	return c.closeErr
}

// apduClient returns the underlying typed APDU client for advanced use.
func (c *Client) apduClient() apdu.Client {
	if c.apduClientOverride != nil {
		return c.apduClientOverride
	}
	return c.rt.Client()
}

// requestBudget returns a context timeout for a single request, derived from
// the invoke timeout and retry count so the context does not fire before the
// library has exhausted its own retries.
func (c *Client) requestBudget() time.Duration {
	return c.cfg.timeout()*time.Duration(c.cfg.retries()+1) + 2*time.Second
}

// pace sleeps for the configured inter-request delay, honoring ctx. It is a
// no-op when pacing is disabled.
func (c *Client) pace(ctx context.Context) {
	if c.cfg.Pacing <= 0 {
		return
	}
	t := time.NewTimer(c.cfg.Pacing)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
