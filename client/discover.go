package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
)

// Device is an ergonomic view of a discovered BACnet device (an I-Am response).
type Device struct {
	// ID is the device object instance (the "BACnet device ID").
	ID uint32
	// Address is the device's BACnet/IP transport address. For a routed device
	// this is the address of the router that serves it.
	Address netip.AddrPort
	// Network is the BACnet network number the device was seen on (0 = local).
	Network uint16
	// MAC is the device's MAC on its own (remote) network, set only for routed
	// devices reached through a router (e.g. one byte for an MS/TP node). It is
	// nil for directly-reachable BACnet/IP devices.
	MAC []byte
	// Vendor is the BACnet vendor identifier.
	Vendor uint16
	// MaxAPDU is the maximum APDU length the device accepts.
	MaxAPDU int
	// Segmentation describes the device's segmentation support.
	Segmentation string
}

// IsRouted reports whether the device is on a remote network reached through a
// router (rather than a directly-reachable BACnet/IP device).
func (d Device) IsRouted() bool { return d.Network != 0 && len(d.MAC) > 0 }

// String renders the device as "device <id> @ <ip:port>".
func (d Device) String() string {
	return fmt.Sprintf("device %d @ %s", d.ID, d.Address)
}

// deviceFromIndication converts a library I-Am indication into a Device.
func deviceFromIndication(ind apdu.IAmIndication) Device {
	return Device{
		ID:           ind.DeviceIdentifier.Instance(),
		Address:      ind.Source.AddrPort,
		Network:      uint16(ind.Source.Network),
		MAC:          ind.Source.MAC,
		Vendor:       ind.VendorID,
		MaxAPDU:      int(ind.MaxAPDULengthAccepted),
		Segmentation: fmt.Sprintf("%v", ind.SegmentationSupported),
	}
}

// address returns the transport Address for this device, preserving routing
// (remote network + MAC) so requests reach it through its router.
func (d Device) address() netprim.Address {
	if d.IsRouted() {
		return netprim.NewRoutedAddress(d.Address, netprim.NetworkNumber(d.Network), d.MAC)
	}
	return netprim.NewAddressFromAddrPort(d.Address)
}

// Target returns a Target addressing this device by its resolved transport
// address, preserving routing (remote network + MAC). Use it to avoid a second
// Who-Is resolution after discovery.
func (d Device) Target() Target {
	return targetForAddress(d.address())
}

// DiscoverOptions configures a Discover call.
type DiscoverOptions struct {
	// Window is how long to collect I-Am responses. Zero uses 5s.
	Window time.Duration
	// Low and High optionally restrict discovery to a device-instance range.
	// Both must be set together; leave both nil for an unbounded Who-Is.
	Low  *uint32
	High *uint32
	// LocalOnly, when true, sends the Who-Is only to the local network instead
	// of as a global broadcast. By default discovery uses a global broadcast
	// (DNET 0xFFFF) so BACnet routers forward it to remote networks (e.g. MS/TP
	// segments), which is required to discover devices behind a router.
	LocalOnly bool
}

// DiscoverOption mutates DiscoverOptions.
type DiscoverOption func(*DiscoverOptions)

// WithWindow sets the discovery collection window.
func WithWindow(d time.Duration) DiscoverOption {
	return func(o *DiscoverOptions) { o.Window = d }
}

// WithInstanceRange restricts discovery to device instances in [low, high].
func WithInstanceRange(low, high uint32) DiscoverOption {
	return func(o *DiscoverOptions) { o.Low, o.High = &low, &high }
}

// WithLocalOnly restricts the Who-Is to the local network (no global broadcast),
// so it is not forwarded by routers. Use this to discover only directly-reachable
// BACnet/IP devices.
func WithLocalOnly() DiscoverOption {
	return func(o *DiscoverOptions) { o.LocalOnly = true }
}

// Discover sends a Who-Is on every broadcast target (all broadcast-capable
// interfaces by default, or the single configured Broadcast address) and
// collects I-Am responses for the window, deduplicated by (device, address).
//
// Results are returned sorted by device ID.
func (c *Client) Discover(ctx context.Context, opts ...DiscoverOption) ([]Device, error) {
	o := DiscoverOptions{Window: defaultWindow}
	for _, opt := range opts {
		opt(&o)
	}
	if o.Window <= 0 {
		o.Window = defaultWindow
	}

	whoIs, err := buildWhoIs(o.Low, o.High)
	if err != nil {
		return nil, err
	}

	targets, err := c.broadcastTargets()
	if err != nil {
		return nil, err
	}
	targets = withGlobalBroadcast(targets, !o.LocalOnly)

	found, err := c.collect(ctx, targets, whoIs, o.Window, 0)
	if err != nil {
		return nil, err
	}

	devices := make([]Device, 0, len(found))
	for _, ind := range found {
		devices = append(devices, deviceFromIndication(ind))
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	return devices, nil
}

// Resolve resolves a BACnet device instance to its Device (including transport
// address) by sending a Who-Is scoped to exactly that instance on every
// broadcast target and collecting I-Am responses for the configured resolve
// window.
//
// Because the Who-Is is limited to a single instance, only the target device
// replies, keeping discovery traffic minimal. It returns an error if no device
// — or more than one device — with that instance answers.
func (c *Client) Resolve(ctx context.Context, deviceInstance uint32) (Device, error) {
	di, err := types.NewDeviceInstance(deviceInstance)
	if err != nil {
		return Device{}, fmt.Errorf("invalid device id %d: %w", deviceInstance, err)
	}
	whoIs, err := apdu.NewWhoIsRequestWithLimits(di, di)
	if err != nil {
		return Device{}, err
	}

	targets, err := c.broadcastTargets()
	if err != nil {
		return Device{}, err
	}
	// Resolve via global broadcast so device IDs on remote networks (e.g. behind
	// a router on MS/TP) can be found, not just local BACnet/IP devices.
	targets = withGlobalBroadcast(targets, true)

	window := c.cfg.resolveWindow()
	found, err := c.collect(ctx, targets, whoIs, window, deviceInstance)
	if err != nil {
		return Device{}, err
	}

	switch len(found) {
	case 0:
		return Device{}, fmt.Errorf(
			"device %d not found (no I-Am within %s); is it online and on a reachable network? You can also address it by IP",
			deviceInstance, window)
	case 1:
		return deviceFromIndication(found[0]), nil
	default:
		addrs := make([]string, 0, len(found))
		for _, f := range found {
			addrs = append(addrs, f.Source.AddrPort.String())
		}
		return Device{}, fmt.Errorf(
			"device %d answered from multiple addresses (%v); address it by IP instead",
			deviceInstance, addrs)
	}
}

// resolveTarget turns a Target into a concrete transport address, resolving a
// device-ID target via Resolve. The returned instance is the device ID when
// known (from an ID target), or 0 for an address target.
func (c *Client) resolveTarget(ctx context.Context, t Target) (netprim.Address, uint32, error) {
	if !t.isID {
		return t.addr, 0, nil
	}
	d, err := c.Resolve(ctx, t.instance)
	if err != nil {
		return netprim.Address{}, 0, err
	}
	// Preserve routing (remote network + MAC) so requests to a device behind a
	// router are sent to the router with the correct NPDU destination.
	return d.address(), d.ID, nil
}

// collect fans out a Who-Is to every target concurrently and merges the I-Am
// responses collected during window. If wantInstance is non-zero, only
// indications for that exact device instance are kept (defensive against
// devices that ignore the Who-Is range). Results are deduplicated by
// (device identifier, network, address).
func (c *Client) collect(ctx context.Context, targets []broadcastTarget, whoIs apdu.WhoIsRequest, window time.Duration, wantInstance uint32) ([]apdu.IAmIndication, error) {
	collectCtx, cancel := context.WithTimeout(ctx, window+2*time.Second)
	defer cancel()

	var (
		mu    sync.Mutex
		seen  = make(map[string]struct{})
		out   []apdu.IAmIndication
		wg    sync.WaitGroup
		anyOK bool
	)

	for _, t := range targets {
		wg.Add(1)
		go func(dst netprim.Address) {
			defer wg.Done()
			inds, err := c.apduClient().Discover(collectCtx, apdu.DiscoverRequest{
				Destination: dst,
				WhoIs:       whoIs,
				Window:      window,
			})
			if err != nil {
				return
			}
			mu.Lock()
			anyOK = true
			for _, ind := range inds {
				if wantInstance != 0 && ind.DeviceIdentifier.Instance() != wantInstance {
					continue
				}
				key := fmt.Sprintf("%d|%d|%s|%x", ind.DeviceIdentifier, ind.Source.Network, ind.Source.AddrPort, ind.Source.MAC)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, ind)
			}
			mu.Unlock()
		}(t.address)
	}
	wg.Wait()

	if !anyOK {
		return nil, fmt.Errorf("could not run discovery on any interface")
	}
	return out, nil
}

// buildWhoIs constructs a Who-Is request, applying an optional instance range.
func buildWhoIs(low, high *uint32) (apdu.WhoIsRequest, error) {
	if low == nil && high == nil {
		return apdu.NewWhoIsRequest(), nil
	}
	if low == nil || high == nil {
		return apdu.WhoIsRequest{}, fmt.Errorf("both low and high must be set to use a device range")
	}
	lo, err := types.NewDeviceInstance(*low)
	if err != nil {
		return apdu.WhoIsRequest{}, fmt.Errorf("invalid low limit: %w", err)
	}
	hi, err := types.NewDeviceInstance(*high)
	if err != nil {
		return apdu.WhoIsRequest{}, fmt.Errorf("invalid high limit: %w", err)
	}
	return apdu.NewWhoIsRequestWithLimits(lo, hi)
}

// broadcastTarget is one Who-Is destination with a short label (interface name,
// or "manual"/"limited-broadcast") for progress reporting.
type broadcastTarget struct {
	label   string
	address netprim.Address
}

// Label returns the human label for the target (interface name, etc.).
func (b broadcastTarget) Label() string { return b.label }

// Address returns the target's transport address.
func (b broadcastTarget) Address() netip.AddrPort { return b.address.AddrPort }

// BroadcastTargets returns the Who-Is destinations that Discover would use,
// with a label per entry. This is exposed so callers (e.g. a CLI) can report
// which interfaces are being probed.
func (c *Client) BroadcastTargets() ([]broadcastTarget, error) {
	return c.broadcastTargets()
}

// withGlobalBroadcast stamps each target's BACnet network number. When enabled,
// the network is set to the global broadcast (0xFFFF) so routers forward the
// Who-Is to every network they serve (reaching e.g. MS/TP devices behind a
// router); the UDP datagram is still sent to the target's IP broadcast address.
// When disabled the targets are returned unchanged (local network only).
func withGlobalBroadcast(targets []broadcastTarget, enabled bool) []broadcastTarget {
	if !enabled {
		return targets
	}
	out := make([]broadcastTarget, len(targets))
	for i, t := range targets {
		t.address.Network = netprim.GlobalBroadcastNetwork
		out[i] = t
	}
	return out
}

// broadcastTargets resolves the set of Who-Is destinations.
//
// If a Broadcast address is configured it is used verbatim. Otherwise the
// directed broadcast address of every broadcast-capable IPv4 interface is used
// (restricted to the configured Interface if set). If nothing can be detected
// it falls back to the limited broadcast 255.255.255.255.
func (c *Client) broadcastTargets() ([]broadcastTarget, error) {
	if len(c.cfg.TransportBroadcasts) > 0 {
		targets := make([]broadcastTarget, len(c.cfg.TransportBroadcasts))
		for i, address := range cloneBACnetAddresses(c.cfg.TransportBroadcasts) {
			targets[i] = broadcastTarget{label: "transport", address: address}
		}
		return targets, nil
	}
	if c.cfg.Broadcast.IsValid() {
		if !c.cfg.Broadcast.Is4() {
			return nil, fmt.Errorf("broadcast %s must be an IPv4 address", c.cfg.Broadcast)
		}
		return []broadcastTarget{{
			label:   "manual",
			address: netprim.NewAddressFromAddrPort(netip.AddrPortFrom(c.cfg.Broadcast, DefaultUDPPort)),
		}}, nil
	}

	var ifaceIP string
	if c.cfg.Interface.IsValid() {
		ifaceIP = c.cfg.Interface.String()
	}

	found, err := detectBroadcasts(ifaceIP)
	if err != nil || len(found) == 0 {
		return []broadcastTarget{{
			label: "limited-broadcast",
			address: netprim.NewAddressFromAddrPort(
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), DefaultUDPPort),
			),
		}}, nil
	}
	return found, nil
}

// detectBroadcasts computes the IPv4 directed-broadcast address for every
// broadcast-capable, non-loopback interface that is up. If ifaceIP is set, only
// the interface holding that address is considered. Duplicate broadcast
// addresses are collapsed.
func detectBroadcasts(ifaceIP string) ([]broadcastTarget, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var want netip.Addr
	if ifaceIP != "" {
		want, err = netip.ParseAddr(ifaceIP)
		if err != nil {
			return nil, err
		}
	}

	var targets []broadcastTarget
	seen := make(map[netip.Addr]struct{})

	for _, iff := range ifaces {
		if iff.Flags&net.FlagUp == 0 || iff.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if iff.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iff.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			cur, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			if want.IsValid() && cur != want {
				continue
			}
			bcastIP := directedBroadcast(ip4, ipnet.Mask)
			b, ok := netip.AddrFromSlice(bcastIP)
			if !ok {
				continue
			}
			if _, dup := seen[b]; dup {
				continue
			}
			seen[b] = struct{}{}
			targets = append(targets, broadcastTarget{
				label:   iff.Name,
				address: netprim.NewAddressFromAddrPort(netip.AddrPortFrom(b, DefaultUDPPort)),
			})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no broadcast-capable IPv4 interface found")
	}
	return targets, nil
}

// directedBroadcast returns ip | ^mask, the directed broadcast address.
func directedBroadcast(ip net.IP, mask net.IPMask) net.IP {
	ip = ip.To4()
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	out := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}
