package netprim

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"

	"github.com/worldiety/bacnet/common/errors"
)

// Address identifies a BACnet station on a local or remote network.
//
// AddrPort is always the BACnet/IP transport peer to which datagrams are sent —
// for a directly-reachable device its own B/IP address, and for a device on a
// remote network (e.g. an MS/TP node) the address of the BACnet router that
// serves that network.
//
// Network is the BACnet network number the station lives on: LocalNetwork (0)
// for a directly-reachable BACnet/IP device, or the remote network number for a
// routed device.
//
// MAC is the station's MAC address on its own network and is only set for
// routed devices (Network != local). It is the DADR/SADR carried in the NPDU
// (e.g. a single byte for an MS/TP node). It is nil for local BACnet/IP
// devices, whose network-layer identity is their B/IP address (see AddrPortBytes).
type Address struct {
	Network  NetworkNumber
	AddrPort netip.AddrPort
	MAC      []byte
}

func NewAddressFromAddrPort(addrPort netip.AddrPort) Address {
	return Address{
		Network:  LocalNetwork,
		AddrPort: addrPort,
	}
}

// NewRoutedAddress constructs an address for a device on a remote BACnet network
// reached through a router. routerAddrPort is the router's B/IP transport
// address (the UDP destination), network is the device's remote network number,
// and mac is the device's MAC on that network (e.g. one byte for MS/TP). A nil
// or empty mac denotes a broadcast on the remote network.
func NewRoutedAddress(routerAddrPort netip.AddrPort, network NetworkNumber, mac []byte) Address {
	return Address{
		Network:  network,
		AddrPort: routerAddrPort,
		MAC:      slices.Clone(mac),
	}
}

// IsRouted reports whether the address denotes a device on a remote network
// reached through a router (a non-local network with a MAC).
func (a Address) IsRouted() bool {
	return !a.Network.IsLocal() && !a.Network.IsGlobalBroadcast() && len(a.MAC) > 0
}

// NewAddress constructs an address and defensively copies the MAC bytes.
func NewAddress(network NetworkNumber, addPort []byte) (Address, error) {
	if len(addPort) != 6 {
		return Address{}, errors.NewValidationError("AddrPort", len(addPort), errors.ErrInvalidBacnetAddress)
	}

	cloned := make([]byte, len(addPort))
	copy(cloned, addPort)

	port := binary.BigEndian.Uint16(addPort[4:6])
	addr := netip.AddrFrom4([4]byte{addPort[0], addPort[1], addPort[2], addPort[3]})

	return Address{
		Network:  network,
		AddrPort: netip.AddrPortFrom(addr, port),
	}, nil
}

// IsLocal reports whether the address belongs to the local BACnet network.
func (a Address) IsLocal() bool {
	return a.Network.IsLocal()
}

// AddrPortBytes returns a defensive copy of the AddrPort address bytes.
func (a Address) AddrPortBytes() []byte {
	bytes := make([]byte, bacNetAddrLen)

	copy(bytes[0:4], a.AddrPort.Addr().AsSlice())
	binary.BigEndian.PutUint16(bytes[4:6], a.AddrPort.Port())

	return bytes
}

func (a Address) Equal(b Address) bool {
	return a.Network == b.Network &&
		slices.Equal(a.AddrPort.Addr().AsSlice(), b.AddrPort.Addr().AsSlice()) &&
		a.AddrPort.Port() == b.AddrPort.Port() &&
		slices.Equal(a.MAC, b.MAC)
}

// String renders the address for logs and diagnostics. Routed devices are shown
// as "<network>:<mac>@<router-ip>"; local devices as their B/IP address.
func (a Address) String() string {
	if a.Network.IsLocal() && len(a.MAC) > 0 {
		return fmt.Sprintf("local:%s", hex.EncodeToString(a.MAC))
	}
	if a.IsRouted() {
		return fmt.Sprintf("%d:%s@%s", a.Network, hex.EncodeToString(a.MAC), a.AddrPort)
	}
	return a.AddrPort.String()
}

// AddrPortToAddress converts a BACnet/IP UDP address into a BACnet local-network address.
//
// Per Annex J of ANSI/ASHRAE 135-2024, each BACnet/IP node is identified by a
// 6-byte B/IP address consisting of the IPv4 address (4 bytes, big-endian) followed
// by the UDP port (2 bytes, big-endian). The returned Address has Network set to
// bacnet.LocalNetwork (0).
//
// addr must be a valid IPv4 address-port pair; IPv6 addresses are not supported.
func AddrPortToAddress(addr netip.AddrPort) (Address, error) {
	if !addr.IsValid() || !addr.Addr().Is4() {
		return Address{}, errors.NewValidationError("addr", addr, errors.ErrInvalidIPAddress)
	}

	return Address{
		Network:  LocalNetwork,
		AddrPort: addr,
	}, nil
}

// bacNetAddrLen is the length of a BACnet/IP MAC address (4-byte IPv4 + 2-byte port).
const bacNetAddrLen = 6
