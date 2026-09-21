package client

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
)

// DefaultUDPPort is the standard BACnet/IP UDP port (0xBAC0).
const DefaultUDPPort = 47808

// Target identifies a BACnet device to address, either by its device instance
// (which must be resolved to a transport address via Who-Is) or directly by a
// BACnet/IP transport address.
//
// Construct a Target with ParseTarget, TargetID, or TargetAddr.
type Target struct {
	isID     bool
	instance uint32
	addr     netprim.Address
}

// TargetID returns a Target that addresses a device by its instance number.
// The address is resolved lazily via Who-Is when the Target is used.
func TargetID(deviceInstance uint32) Target {
	return Target{isID: true, instance: deviceInstance}
}

// TargetAddr returns a Target that addresses a device by its transport address.
func TargetAddr(ap netip.AddrPort) Target {
	return Target{addr: netprim.NewAddressFromAddrPort(ap)}
}

// TargetAddress returns a target for an already constructed BACnet address.
// It supports native transports as well as routed BACnet/IP addresses.
func TargetAddress(address netprim.Address) Target {
	return targetForAddress(address)
}

// targetForAddress returns a Target that addresses a device by an already
// resolved transport address, preserving any routing (remote network + MAC).
func targetForAddress(addr netprim.Address) Target {
	return Target{addr: addr}
}

// IsID reports whether the target is a device ID (requiring resolution).
func (t Target) IsID() bool { return t.isID }

// Instance returns the device instance for an ID target (0 otherwise).
func (t Target) Instance() uint32 { return t.instance }

// String renders the target for display.
func (t Target) String() string {
	if t.isID {
		return fmt.Sprintf("device %d", t.instance)
	}
	return t.addr.AddrPort.String()
}

// ParseTarget parses a device reference, auto-detecting whether it is a BACnet
// device ID or a BACnet/IP transport address.
//
// Accepted forms:
//
//	10.6.6.123          -> IP transport address, port 47808
//	10.6.6.123:47809    -> IP transport address, explicit port
//	5123                -> device ID (instance 5123)
//	device:5123         -> device ID (explicit)
//	#5123               -> device ID (explicit)
//
// Disambiguation: any value containing a dot is treated as an IPv4 address;
// otherwise it is treated as a device ID.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty device")
	}

	// Explicit device-ID forms.
	if rest, ok := strings.CutPrefix(s, "#"); ok {
		return parseIDTarget(rest)
	}
	if rest, ok := cutPrefixFold(s, "device:"); ok {
		return parseIDTarget(rest)
	}

	// A dot means an IPv4 transport address; otherwise a bare device ID.
	if strings.Contains(s, ".") {
		ap, err := parseAddrPort(s)
		if err != nil {
			return Target{}, err
		}
		return TargetAddr(ap), nil
	}

	return parseIDTarget(s)
}

func parseIDTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	inst, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return Target{}, fmt.Errorf("invalid device id %q: expected a number, device:N, #N, or an IP address", s)
	}
	di, err := types.NewDeviceInstance(uint32(inst))
	if err != nil {
		return Target{}, fmt.Errorf("invalid device id %q: %w", s, err)
	}
	return TargetID(uint32(di)), nil
}

// parseAddrPort parses a BACnet/IP transport address ("ip" or "ip:port").
func parseAddrPort(s string) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, ":") {
		if _, err := netip.ParseAddr(s); err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid device address %q: %w", s, err)
		}
		s = fmt.Sprintf("%s:%d", s, DefaultUDPPort)
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid device address %q: %w", s, err)
	}
	if !ap.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf("device address %q must be IPv4 (BACnet/IP)", s)
	}
	return ap, nil
}

// cutPrefixFold is strings.CutPrefix with case-insensitive prefix matching.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// Object identifies a BACnet object by type and instance.
type Object struct {
	Type     types.ObjectType
	Instance uint32
}

// NewObject constructs a validated Object.
func NewObject(ot types.ObjectType, instance uint32) (Object, error) {
	if _, err := types.NewObjectIdentifier(ot, instance); err != nil {
		return Object{}, err
	}
	return Object{Type: ot, Instance: instance}, nil
}

// OID returns the packed BACnet object identifier.
func (o Object) OID() types.ObjectIdentifier {
	// Both fields are validated on construction; ignore the (impossible) error.
	oid, _ := types.NewObjectIdentifier(o.Type, o.Instance)
	return oid
}

// String renders the object as "type:instance" (e.g. "analog-value:1").
func (o Object) String() string {
	return fmt.Sprintf("%s:%d", ObjectTypeName(o.Type), o.Instance)
}

// objectFromOID converts a packed identifier back to an Object.
func objectFromOID(oid types.ObjectIdentifier) Object {
	return Object{Type: oid.ObjectType(), Instance: oid.Instance()}
}

// ParseObject parses an object identifier in the form "type:instance".
//
// The type may be a known name (e.g. "analog-value", "device") or a raw numeric
// object-type value (e.g. "2"). The instance is an unsigned integer.
func ParseObject(s string) (Object, error) {
	s = strings.TrimSpace(s)
	typePart, instPart, ok := strings.Cut(s, ":")
	if !ok {
		return Object{}, fmt.Errorf("invalid object %q: expected <type>:<instance> (e.g. analog-value:1)", s)
	}

	ot, err := parseObjectType(typePart)
	if err != nil {
		return Object{}, err
	}

	inst, err := strconv.ParseUint(strings.TrimSpace(instPart), 10, 32)
	if err != nil {
		return Object{}, fmt.Errorf("invalid object instance %q: %w", instPart, err)
	}

	return NewObject(ot, uint32(inst))
}

// parseObjectType resolves an object type from a name or a numeric value.
func parseObjectType(s string) (types.ObjectType, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty object type")
	}

	if ot, ok := objectTypeByName[s]; ok {
		return ot, nil
	}

	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		ot := types.ObjectType(n)
		if !ot.Valid() {
			return 0, fmt.Errorf("object type %d out of range (max %d)", n, types.ObjectTypeMax)
		}
		return ot, nil
	}

	return 0, fmt.Errorf("unknown object type %q (try a name like analog-input or a number)", s)
}

// ParseProperty resolves a property identifier from a name or numeric value.
func ParseProperty(s string) (types.PropertyIdentifier, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty property identifier")
	}

	if pid, ok := propertyByName[s]; ok {
		return pid, nil
	}

	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return types.PropertyIdentifier(n), nil
	}

	return 0, fmt.Errorf("unknown property %q (try a name like present-value or a number)", s)
}
