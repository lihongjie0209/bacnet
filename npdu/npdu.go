package npdu

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/log"
	"github.com/worldiety/bacnet/common/netprim"
)

// PayloadKind identifies whether the NPDU carries application payload bytes or
// a network layer message payload.
type PayloadKind uint8

const (
	// PayloadKindApplication carries opaque higher-layer (typically APDU) bytes.
	PayloadKindApplication PayloadKind = iota
	// PayloadKindNetworkLayerMessage carries network-layer-message payload bytes.
	PayloadKindNetworkLayerMessage
)

func (k PayloadKind) String() string {
	switch k {
	case PayloadKindApplication:
		return "application"
	case PayloadKindNetworkLayerMessage:
		return "network-layer-message"
	default:
		return fmt.Sprintf("payload-kind(%d)", k)
	}
}

// NetworkLayerMessageType identifies the NPDU network layer message type byte.
type NetworkLayerMessageType uint8

const (
	NetworkLayerMessageTypeWhoIsRouterToNetwork          NetworkLayerMessageType = 0x00
	NetworkLayerMessageTypeIAmRouterToNetwork            NetworkLayerMessageType = 0x01
	NetworkLayerMessageTypeICouldBeRouterToNetwork       NetworkLayerMessageType = 0x02
	NetworkLayerMessageTypeRejectMessageToNetwork        NetworkLayerMessageType = 0x03
	NetworkLayerMessageTypeRouterBusyToNetwork           NetworkLayerMessageType = 0x04
	NetworkLayerMessageTypeRouterAvailableToNetwork      NetworkLayerMessageType = 0x05
	NetworkLayerMessageTypeInitializeRoutingTable        NetworkLayerMessageType = 0x06
	NetworkLayerMessageTypeInitializeRoutingTableAck     NetworkLayerMessageType = 0x07
	NetworkLayerMessageTypeEstablishConnectionToNetwork  NetworkLayerMessageType = 0x08
	NetworkLayerMessageTypeDisconnectConnectionToNetwork NetworkLayerMessageType = 0x09
	NetworkLayerMessageTypeWhatIsNetworkNumber           NetworkLayerMessageType = 0x12
	NetworkLayerMessageTypeNetworkNumberIs               NetworkLayerMessageType = 0x13
	NetworkLayerMessageTypeAshraeReserved                NetworkLayerMessageType = 0x14
	NetworkLayerMessageTypeVendorProprietary             NetworkLayerMessageType = 0x80
)

// IsProprietary reports whether the message type requires a VendorID in NPCI.
func (t NetworkLayerMessageType) IsProprietary() bool {
	return t >= NetworkLayerMessageTypeVendorProprietary
}

// IsReserved reports whether the message type is reserved for future use (and thus currently invalid)
func (t NetworkLayerMessageType) IsReserved() bool {
	return t >= NetworkLayerMessageTypeAshraeReserved && t < NetworkLayerMessageTypeVendorProprietary ||
		t > NetworkLayerMessageTypeDisconnectConnectionToNetwork && t < NetworkLayerMessageTypeWhatIsNetworkNumber
}

// ValidStandard reports whether t is one of the known standard BACnet NLM types.
func (t NetworkLayerMessageType) ValidStandard() bool {
	switch t {
	case NetworkLayerMessageTypeWhoIsRouterToNetwork,
		NetworkLayerMessageTypeIAmRouterToNetwork,
		NetworkLayerMessageTypeICouldBeRouterToNetwork,
		NetworkLayerMessageTypeRejectMessageToNetwork,
		NetworkLayerMessageTypeRouterBusyToNetwork,
		NetworkLayerMessageTypeRouterAvailableToNetwork,
		NetworkLayerMessageTypeInitializeRoutingTable,
		NetworkLayerMessageTypeInitializeRoutingTableAck,
		NetworkLayerMessageTypeEstablishConnectionToNetwork,
		NetworkLayerMessageTypeDisconnectConnectionToNetwork,
		NetworkLayerMessageTypeWhatIsNetworkNumber,
		NetworkLayerMessageTypeNetworkNumberIs:
		return true
	default:
		return false
	}
}

func (t NetworkLayerMessageType) String() string {
	switch t {
	case NetworkLayerMessageTypeWhoIsRouterToNetwork:
		return "who-is-router-to-network"
	case NetworkLayerMessageTypeIAmRouterToNetwork:
		return "i-am-router-to-network"
	case NetworkLayerMessageTypeICouldBeRouterToNetwork:
		return "i-could-be-router-to-network"
	case NetworkLayerMessageTypeRejectMessageToNetwork:
		return "reject-message-to-network"
	case NetworkLayerMessageTypeRouterBusyToNetwork:
		return "router-busy-to-network"
	case NetworkLayerMessageTypeRouterAvailableToNetwork:
		return "router-available-to-network"
	case NetworkLayerMessageTypeInitializeRoutingTable:
		return "initialize-routing-table"
	case NetworkLayerMessageTypeInitializeRoutingTableAck:
		return "initialize-routing-table-ack"
	case NetworkLayerMessageTypeEstablishConnectionToNetwork:
		return "establish-connection-to-network"
	case NetworkLayerMessageTypeDisconnectConnectionToNetwork:
		return "disconnect-connection-to-network"
	case NetworkLayerMessageTypeWhatIsNetworkNumber:
		return "what-is-network-number"
	case NetworkLayerMessageTypeNetworkNumberIs:
		return "network-number-is"
	default:
		if t.IsProprietary() {
			return fmt.Sprintf("proprietary-network-layer-message-type(%d)", t)
		}
		return fmt.Sprintf("network-layer-message-type(%d)", t)
	}
}

// NlmRejectReason is the reason code embedded in a Reject-Message-To-Network NLM
// per clause 6.6.4 of ANSI/ASHRAE 135-2024. It is distinct from the APDU-level
// RejectReason type and must not be used interchangeably with it.
type NlmRejectReason uint8

const (
	// NLMRejectReasonOther indicates an unspecified rejection cause.
	NLMRejectReasonOther NlmRejectReason = 0
	// NLMRejectReasonTooManyHops indicates that the hop count was exhausted before the
	// message could reach its destination network.
	NLMRejectReasonTooManyHops NlmRejectReason = 1
	// NLMRejectReasonRouterBusy indicates that the router has no buffer space to relay
	// the message.
	NLMRejectReasonRouterBusy NlmRejectReason = 2
	// NLMRejectReasonUnknownMessageType indicates that the network-layer message type
	// is not known to this router and cannot be relayed.
	NLMRejectReasonUnknownMessageType NlmRejectReason = 3
	// NLMRejectReasonMessageTooLong indicates that the message exceeds the maximum
	// permissible length for the destination network.
	NLMRejectReasonMessageTooLong NlmRejectReason = 4
)

// ValidStandard reports whether r is a defined NLM reject reason code per clause 6.6.4.
func (r NlmRejectReason) ValidStandard() bool {
	return r <= NLMRejectReasonMessageTooLong
}

// String returns the hyphen-separated BACnet name for the NLM reject reason, or a
// fallback of the form "nlm-reject-reason(N)" for unknown values.
func (r NlmRejectReason) String() string {
	switch r {
	case NLMRejectReasonOther:
		return "other"
	case NLMRejectReasonTooManyHops:
		return "too-many-hops"
	case NLMRejectReasonRouterBusy:
		return "router-busy"
	case NLMRejectReasonUnknownMessageType:
		return "unknown-message-type"
	case NLMRejectReasonMessageTooLong:
		return "message-too-long"
	default:
		return fmt.Sprintf("nlm-reject-reason(%d)", r)
	}
}

// DestinationSpecifier models optional routed-destination fields in NPCI.
type DestinationSpecifier struct {
	DNET     UltimateDestinationNetworkNumber
	DADR     UltimateDestinationMacLayerAddress
	HopCount uint8
}

// SourceSpecifier models optional routed-source fields in NPCI.
type SourceSpecifier struct {
	SNET OriginalSourceNetworkNumber
	SADR OriginalSourceMacLayerAddress
}

// NPCI models NPDU control and optional routed addressing metadata.
type NPCI struct {
	Priority       netprim.NetworkPriority
	ExpectingReply bool
	Destination    *DestinationSpecifier
	Source         *SourceSpecifier
}

// NetworkLayerMessageHeader models network-layer-message header semantics.
type NetworkLayerMessageHeader struct {
	MessageType NetworkLayerMessageType
	VendorID    *uint16
}

func (h NetworkLayerMessageHeader) structureValid() bool {
	if h.MessageType.IsProprietary() {
		return h.VendorID != nil
	}

	return h.VendorID == nil
}

// minNpduLen is the minimum wire size of an NPDU (version byte + NPCI byte).
const minNpduLen = 2

// NetworkLayerProtocolDataUnit represents a decoded BACnet NPDU per clause 6.2.2 of
// ANSI/ASHRAE 135-2024. The zero value is invalid; use a constructor or Decode.
//
// Slice ownership: payload/address bytes are owned by the NPDU value after
// construction/decode. Public accessors return defensive copies.
type NetworkLayerProtocolDataUnit struct {
	// protocolVersion is always bacnet.ProtocolVersion (0x01).
	protocolVersion uint8
	flags           NPCIFieldsFlags

	dnet *UltimateDestinationNetworkNumber
	dlen *UltimateDestinationNetworkNumberMacAddressLength
	dadr UltimateDestinationMacLayerAddress

	snet *OriginalSourceNetworkNumber
	slen *OriginalSourceNetworkNumberMacAddressLength
	sadr OriginalSourceMacLayerAddress

	hopCount    *uint8
	messageType *uint8
	vendorId    *uint16
	apdu        []byte
}

func (n *NetworkLayerProtocolDataUnit) String() string {
	//todo make optional fields output conditional
	str := fmt.Sprintf("NetworkLayerProtocolDataUnit(0x%x)\n", n.protocolVersion)
	str += fmt.Sprintf(", flags: 0x%s\n", n.flags)

	if n.flags&destinationSpecifierMask != 0 && n.dnet != nil && n.dlen != nil {
		str += fmt.Sprintf(", dnet: %v\n", *n.dnet)
		str += fmt.Sprintf(", dlen: %v\n", *n.dlen)
		if n.hopCount != nil {
			str += fmt.Sprintf(", hopCount: %v\n", *n.hopCount)
		}

		if n.dlen != nil && *n.dlen > 0 {
			str += fmt.Sprintf(", dadr: %s\n", string(n.dadr))
		}
	}

	if n.flags&sourceSpecifierMask != 0 && n.snet != nil && n.slen != nil {
		str += fmt.Sprintf(", snet: %v\n", *n.snet)
		str += fmt.Sprintf(", slen: %v\n", *n.slen)
		str += fmt.Sprintf(", sadr: %s\n", string(n.sadr))
	}

	if n.flags&isNetworkLayerMessageMask != 0 && n.messageType != nil {
		str += fmt.Sprintf(", messageType: %v\n", *n.messageType)
	}

	return str
}

// Valid reports whether the NPDU holds a consistent, encodable state per clause 6.2.2.
// It verifies protocol version, reserved-bit constraints, and field-presence rules.
func (n *NetworkLayerProtocolDataUnit) Valid() bool {
	if n == nil {
		return false
	}

	// Protocol version must match exactly
	if n.protocolVersion != netprim.ProtocolVersion {
		return false
	}

	// Bits 4 and 6 are reserved and must be zero per the standard.
	if n.flags&reservedBit4Mask != 0 || n.flags&reservedBit6Mask != 0 {
		return false
	}

	// Bit 7: network layer message flag.
	msgTypePresent := n.flags&isNetworkLayerMessageMask != 0
	if msgTypePresent {
		if n.messageType == nil {
			return false
		}

		// VendorID is required for proprietary message types (>= 0x80) and
		// must be absent for standard types (< 0x80).
		if *n.messageType >= 0x80 {
			if n.vendorId == nil {
				return false
			}
		} else {
			if n.vendorId != nil {
				return false
			}
		}
	} else {
		if n.messageType != nil || n.vendorId != nil {
			return false
		}
	}

	if msgTypePresent {
		header := NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(*n.messageType)}
		if n.vendorId != nil {
			header.VendorID = ptr(*n.vendorId)
		}

		if err := validateNetworkLayerMessagePayload(header, n.apdu); err != nil {
			return false
		}
	}

	// Bit 5: destination specifier — DNET, DLEN, DADR, HopCount all present or all absent.
	dstSpecifier := n.flags&destinationSpecifierMask != 0
	if dstSpecifier {
		if n.dnet == nil || n.dlen == nil || n.hopCount == nil {
			return false
		}

		if *n.dnet == 0 {
			return false
		}

		if *n.dlen == 0 {
			// DLEN == 0 means broadcast on DNET (either a specific network or the global
			// broadcast address 0xFFFF); DADR must be absent in both cases.
			if n.dadr != nil {
				return false
			}
		} else {
			// DLEN > 0: DADR must be present and exactly DLEN bytes long.
			// Global broadcast (0xFFFF) combined with a specific DADR is illegal; the
			// decoder already rejects such frames on ingress.
			if netprim.NetworkNumber(*n.dnet).IsGlobalBroadcast() {
				return false
			}
			if n.dadr == nil || len(n.dadr) != int(*n.dlen) {
				return false
			}
		}
	} else {
		if n.dnet != nil || n.dlen != nil || n.dadr != nil || n.hopCount != nil {
			return false
		}
	}

	// Bit 3: source specifier — SNET, SLEN, SADR all present or all absent.
	srcSpecifier := n.flags&sourceSpecifierMask != 0
	if srcSpecifier {
		if n.snet == nil || n.slen == nil {
			return false
		}
		// SLEN must be > 0; source broadcasts are not permitted per the standard.
		if *n.slen == 0 {
			return false
		}

		if n.sadr == nil || len(n.sadr) != int(*n.slen) {
			return false
		}

		if !n.snet.Valid() {
			return false
		}
	} else {
		if n.snet != nil || n.slen != nil || n.sadr != nil {
			return false
		}
	}

	return true
}

// Encode serializes the NPDU to its wire representation per clause 6.2.2.
// Returns ErrEncodeFailure if the NPDU is not Valid().
func (n *NetworkLayerProtocolDataUnit) Encode() ([]byte, error) {
	if !n.Valid() {
		log.Logger.Error("npdu encode invalid state", "error", ErrEncodeFailure)
		return nil, fmt.Errorf("%w: npdu is not in a valid state", ErrEncodeFailure)
	}

	dstSpecifier := n.flags&destinationSpecifierMask != 0
	srcSpecifier := n.flags&sourceSpecifierMask != 0
	nlMsg := n.flags&isNetworkLayerMessageMask != 0

	// Pre-calculate wire size to avoid reallocations.
	size := 2 // version + NPCI
	if dstSpecifier {
		size += 2 + 1 + len(n.dadr) // DNET + DLEN + DADR
	}
	if srcSpecifier {
		size += 2 + 1 + len(n.sadr) // SNET + SLEN + SADR
	}
	if dstSpecifier {
		size++ // HopCount
	}
	if nlMsg {
		size++ // MessageType
		if *n.messageType >= 0x80 {
			size += 2 // VendorID
		}
	}
	size += len(n.apdu)

	out := make([]byte, size)
	i := 0

	out[i] = n.protocolVersion
	i++
	out[i] = uint8(n.flags)
	i++

	if dstSpecifier {
		binary.BigEndian.PutUint16(out[i:], uint16(*n.dnet))
		i += 2
		out[i] = uint8(*n.dlen)
		i++
		copy(out[i:], n.dadr)
		i += len(n.dadr)
	}

	if srcSpecifier {
		binary.BigEndian.PutUint16(out[i:], uint16(*n.snet))
		i += 2
		out[i] = uint8(*n.slen)
		i++
		copy(out[i:], n.sadr)
		i += len(n.sadr)
	}

	if dstSpecifier {
		out[i] = *n.hopCount
		i++
	}

	if nlMsg {
		out[i] = *n.messageType
		i++
		if *n.messageType >= 0x80 {
			binary.BigEndian.PutUint16(out[i:], *n.vendorId)
			i += 2
		}
	}

	copy(out[i:], n.apdu)
	return out, nil
}

// Decode parses raw wire bytes into the receiver per clause 6.2.2.
// data must contain exactly one complete NPDU. Returns ErrDecodeFailure (or a
// more specific sentinel) on malformed input.
func (n *NetworkLayerProtocolDataUnit) Decode(data []byte) error {
	if n == nil {
		log.Logger.Error("npdu decode nil receiver", "error", ErrDecodeFailure)
		return fmt.Errorf("%w: cannot decode into nil pointer", ErrDecodeFailure)
	}
	log.Logger.Debug("npdu decode inbound", "bytes", len(data))
	if len(data) < minNpduLen {
		return errors.NewValidationError("data", len(data), ErrInvalidLength)
	}

	res := NetworkLayerProtocolDataUnit{}
	i := 0

	res.protocolVersion = data[i]
	i++
	if res.protocolVersion != netprim.ProtocolVersion {
		return errors.NewValidationError("protocol version", res.protocolVersion, ErrInvalidProtocolVersion)
	}

	res.flags = NPCIFieldsFlags(data[i])
	i++
	if res.flags&reservedBit4Mask != 0 || res.flags&reservedBit6Mask != 0 {
		return errors.NewValidationError("NPCI", res.flags, ErrReservedBitSet)
	}

	dstSpecifier := res.flags&destinationSpecifierMask != 0
	srcSpecifier := res.flags&sourceSpecifierMask != 0
	nlMsg := res.flags&isNetworkLayerMessageMask != 0

	// Destination specifier: DNET (2) + DLEN (1) + DADR (DLEN bytes).
	if dstSpecifier {
		if i+3 > len(data) {
			return fmt.Errorf("%w: truncated DNET/DLEN", ErrDecodeFailure)
		}

		res.dnet = ptr(UltimateDestinationNetworkNumber(binary.BigEndian.Uint16(data[i:])))
		if *res.dnet == 0 {
			return errors.NewValidationError("dnet", *res.dnet, ErrInvalidNetworkNumber)
		}
		i += 2

		res.dlen = ptr(UltimateDestinationNetworkNumberMacAddressLength(data[i]))
		i++

		if *res.dlen > 0 {
			//reject global broadcast for non-zero DLEN
			if netprim.NetworkNumber(*res.dnet).IsGlobalBroadcast() {
				return errors.NewValidationError("dnet", *res.dnet, ErrInvalidNetworkNumber)
			}

			if i+int(*res.dlen) > len(data) {
				return fmt.Errorf("%w: truncated DADR", ErrDecodeFailure)
			}
			res.dadr = slices.Clone(data[i : i+int(*res.dlen)])
			i += int(*res.dlen)
		}
	}

	// Source specifier: SNET (2) + SLEN (1) + SADR (SLEN bytes).
	if srcSpecifier {
		if i+3 > len(data) {
			return fmt.Errorf("%w: truncated SNET/SLEN", ErrDecodeFailure)
		}

		snet := OriginalSourceNetworkNumber(binary.BigEndian.Uint16(data[i:]))
		if !snet.Valid() {
			return errors.NewValidationError("snet", snet, ErrInvalidNetworkNumber)
		}

		res.snet = &snet
		i += 2

		slen := OriginalSourceNetworkNumberMacAddressLength(data[i])
		i++
		if slen == 0 {
			return errors.NewValidationError("SLEN", slen, ErrInvalidLength)
		}

		res.slen = &slen

		if i+int(slen) > len(data) {
			return fmt.Errorf("%w: truncated SADR", ErrDecodeFailure)
		}

		res.sadr = slices.Clone(data[i : i+int(slen)])
		i += int(slen)
	}

	// HopCount follows the address fields and is present only with a destination specifier.
	if dstSpecifier {
		if i >= len(data) {
			return fmt.Errorf("%w: truncated HopCount", ErrDecodeFailure)
		}
		res.hopCount = ptr(data[i])
		i++
	}

	// Network layer message type, and VendorID for proprietary types (>= 0x80).
	if nlMsg {
		if i >= len(data) {
			return fmt.Errorf("%w: truncated MessageType", ErrDecodeFailure)
		}
		mt := data[i]
		i++
		res.messageType = &mt

		if mt >= 0x80 {
			if i+2 > len(data) {
				return fmt.Errorf("%w: truncated VendorID", ErrDecodeFailure)
			}

			res.vendorId = ptr(binary.BigEndian.Uint16(data[i:]))
			i += 2
		}
	}

	// Remaining bytes are the APDU or NL message data.
	if i < len(data) {
		res.apdu = slices.Clone(data[i:])
	}
	if nlMsg {
		header := NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(*res.messageType)}
		if res.vendorId != nil {
			header.VendorID = ptr(*res.vendorId)
		}
		if err := validateNetworkLayerMessagePayload(header, res.apdu); err != nil {
			log.Logger.Error("npdu decode validate network-layer payload", "error", err)
			return fmt.Errorf("%w: %v", ErrDecodeFailure, err)
		}
	}

	log.Logger.Debug(
		"npdu decode success",
		"flags", uint8(res.flags),
		"has_destination", dstSpecifier,
		"has_source", srcSpecifier,
		"is_network_layer_message", nlMsg,
		"message_type", res.messageType,
		"vendor_id", res.vendorId,
		"payload_bytes", len(res.apdu),
	)
	*n = res
	return nil
}

// --- Constructors ---

// NewLocalAPDU constructs an NPDU carrying a local (non-routed) BACnet APDU.
// This is the most common form for BACnet/IP devices communicating on the same subnet.
// priority controls the NPCI priority field. expectingReply sets the Expecting-Reply bit.
// apdu must be non-empty.
func NewLocalAPDU(priority netprim.NetworkPriority, expectingReply bool, apdu []byte) (*NetworkLayerProtocolDataUnit, error) {
	return NewApplicationNPDU(NPCI{Priority: priority, ExpectingReply: expectingReply}, apdu)
}

// NewRoutedAPDU constructs an NPDU carrying a BACnet APDU addressed to a remote network.
// dadr may be nil or empty to request a broadcast on dnet (DLEN = 0).
// hopCount is the initial hop count (typically 255). apdu must be non-empty.
func NewRoutedAPDU(
	dnet UltimateDestinationNetworkNumber,
	dadr UltimateDestinationMacLayerAddress,
	hopCount uint8,
	priority netprim.NetworkPriority,
	expectingReply bool,
	apdu []byte,
) (*NetworkLayerProtocolDataUnit, error) {
	return NewApplicationNPDU(
		NPCI{
			Priority:       priority,
			ExpectingReply: expectingReply,
			Destination: &DestinationSpecifier{
				DNET:     dnet,
				DADR:     dadr,
				HopCount: hopCount,
			},
		},
		apdu,
	)
}

// NewSourcedAPDU constructs an NPDU carrying a local (non-routed) BACnet APDU
// with an explicit source specifier (SNET/SLEN/SADR).
func NewSourcedAPDU(
	snet OriginalSourceNetworkNumber,
	sadr OriginalSourceMacLayerAddress,
	priority netprim.NetworkPriority,
	expectingReply bool,
	apdu []byte,
) (*NetworkLayerProtocolDataUnit, error) {
	return NewApplicationNPDU(
		NPCI{
			Priority:       priority,
			ExpectingReply: expectingReply,
			Source: &SourceSpecifier{
				SNET: snet,
				SADR: sadr,
			},
		},
		apdu,
	)
}

// NewRoutedSourcedAPDU constructs an NPDU carrying a routed BACnet APDU with
// both destination and source specifiers present.
func NewRoutedSourcedAPDU(
	dnet UltimateDestinationNetworkNumber,
	dadr UltimateDestinationMacLayerAddress,
	hopCount uint8,
	snet OriginalSourceNetworkNumber,
	sadr OriginalSourceMacLayerAddress,
	priority netprim.NetworkPriority,
	expectingReply bool,
	apdu []byte,
) (*NetworkLayerProtocolDataUnit, error) {
	return NewApplicationNPDU(
		NPCI{
			Priority:       priority,
			ExpectingReply: expectingReply,
			Destination: &DestinationSpecifier{
				DNET:     dnet,
				DADR:     dadr,
				HopCount: hopCount,
			},
			Source: &SourceSpecifier{
				SNET: snet,
				SADR: sadr,
			},
		},
		apdu,
	)
}

// NewNetworkLayerMessage constructs an NPDU carrying a standard network layer message
// (messageType < 0x80). For proprietary types use NewProprietaryNetworkLayerMessage.
// data may be nil for message types that carry no payload.
func NewNetworkLayerMessage(messageType uint8, data []byte, priority netprim.NetworkPriority) (*NetworkLayerProtocolDataUnit, error) {
	if messageType >= 0x80 {
		return nil, errors.NewValidationError("message type", messageType, ErrProprietaryMessageType)
	}
	return NewNetworkLayerNPDU(
		NPCI{Priority: priority},
		NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(messageType)},
		data,
	)
}

// NewProprietaryNetworkLayerMessage constructs an NPDU carrying a proprietary network
// layer message (messageType >= 0x80). vendorID identifies the originating vendor.
// data may be nil.
func NewProprietaryNetworkLayerMessage(messageType uint8, vendorID uint16, data []byte, priority netprim.NetworkPriority) (*NetworkLayerProtocolDataUnit, error) {
	if messageType < 0x80 {
		return nil, errors.NewValidationError("message type", messageType, ErrInvalidMessage)
	}
	return NewNetworkLayerNPDU(
		NPCI{Priority: priority},
		NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(messageType), VendorID: ptr(vendorID)},
		data,
	)
}

// NewApplicationNPDU constructs an NPDU carrying opaque application payload bytes.
// The network layer does not interpret the application payload.
func NewApplicationNPDU(npci NPCI, payload []byte) (*NetworkLayerProtocolDataUnit, error) {
	if npci.Priority > netprim.NetworkPriorityLifeSafety {
		return nil, errors.NewValidationError("priority", npci.Priority, ErrInvalidPriority)
	}

	if len(payload) == 0 {
		return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
	}

	n, err := newNPDUWithNPCI(npci)
	if err != nil {
		log.Logger.Error("npdu new application with npci", "error", err)
		return nil, err
	}

	n.apdu = slices.Clone(payload)
	return n, nil
}

// NewNetworkLayerNPDU constructs an NPDU carrying network-layer-message payload bytes.
// The payload bytes remain opaque at NPDU scope.
func NewNetworkLayerNPDU(npci NPCI, header NetworkLayerMessageHeader, payload []byte) (*NetworkLayerProtocolDataUnit, error) {
	if npci.Priority > netprim.NetworkPriorityLifeSafety {
		return nil, errors.NewValidationError("priority", npci.Priority, ErrInvalidPriority)
	}

	if !header.structureValid() {
		return nil, errors.NewValidationError("network layer message header", header, ErrInvalidMessage)
	}

	normalizedPayload, err := decodeAndNormalizeNetworkLayerMessagePayload(header, payload)
	if err != nil {
		log.Logger.Error("npdu normalize network-layer payload", "error", err)
		return nil, errors.NewValidationError("payload", "actual payload omitted from error", err)
	}

	n, err := newNPDUWithNPCI(npci)
	if err != nil {
		log.Logger.Error("npdu new network-layer with npci", "error", err)
		return nil, err
	}
	n.flags |= isNetworkLayerMessageMask
	n.messageType = ptr(uint8(header.MessageType))
	if header.VendorID != nil {
		n.vendorId = ptr(*header.VendorID)
	}
	n.apdu = normalizedPayload
	return n, nil
}

// NewNetworkLayerNPDUFromMessage constructs an NPDU from a typed network-layer-message model.
func NewNetworkLayerNPDUFromMessage(npci NPCI, message NetworkLayerMessageModel) (*NetworkLayerProtocolDataUnit, error) {
	if message == nil {
		return nil, errors.NewValidationError("message", nil, ErrInvalidMessage)
	}
	if !message.Valid() {
		return nil, errors.NewValidationError("message", message, ErrInvalidMessage)
	}

	header := MustNetworkLayerMessageHeader(message)
	return NewNetworkLayerNPDU(npci, header, message.PayloadBytes())
}

func newNPDUWithNPCI(npci NPCI) (*NetworkLayerProtocolDataUnit, error) {
	flags := NPCIFieldsFlags(npci.Priority)
	if npci.ExpectingReply {
		flags |= expectingReplyMask
	}

	n := &NetworkLayerProtocolDataUnit{
		protocolVersion: netprim.ProtocolVersion,
		flags:           flags,
	}

	if npci.Destination != nil {
		dnet := npci.Destination.DNET

		dlen := len(npci.Destination.DADR)

		if netprim.NetworkNumber(dnet).IsLocal() {
			return nil, errors.NewValidationError("dnet", dnet, ErrInvalidNetworkNumber)
		}

		if dlen > 255 {
			return nil, errors.NewValidationError("dlen", len(npci.Destination.DADR), ErrInvalidLength)
		}

		if netprim.NetworkNumber(dnet).IsGlobalBroadcast() {
			if dlen != 0 {
				return nil, errors.NewValidationError("dlen", fmt.Sprintf("dlen == %v, despite global broadcast, should be 0", dlen), ErrInvalidLength)
			}
		}

		hopCount := npci.Destination.HopCount
		if hopCount == 0 {
			return nil, errors.NewValidationError("hop count", hopCount, ErrInvalidHopCount)
		}

		n.flags |= destinationSpecifierMask
		n.dnet = &dnet
		n.dlen = ptr(UltimateDestinationNetworkNumberMacAddressLength(dlen))
		n.hopCount = &hopCount
		if len(npci.Destination.DADR) > 0 {
			n.dadr = slices.Clone(npci.Destination.DADR)
		}
	}

	if npci.Source != nil {
		slen := len(npci.Source.SADR)

		if slen == 0 || slen > 255 {
			return nil, errors.NewValidationError("sadr", len(npci.Source.SADR), ErrInvalidLength)
		}

		snet := npci.Source.SNET
		if !snet.Valid() {
			return nil, errors.NewValidationError("snet", snet, ErrInvalidNetworkNumber)
		}

		n.flags |= sourceSpecifierMask
		n.snet = &snet
		n.slen = ptr(OriginalSourceNetworkNumberMacAddressLength(slen))
		n.sadr = slices.Clone(npci.Source.SADR)
	}

	return n, nil
}

// --- Accessors ---

// Version returns the protocol version byte (always bacnet.ProtocolVersion for valid NPDUs).
func (n *NetworkLayerProtocolDataUnit) Version() uint8 { return n.protocolVersion }

// Flags returns the raw NPCI control byte.
func (n *NetworkLayerProtocolDataUnit) Flags() NPCIFieldsFlags { return n.flags }

// Priority returns the 2-bit network priority from the NPCI.
func (n *NetworkLayerProtocolDataUnit) Priority() netprim.NetworkPriority {
	return netprim.NetworkPriority(n.flags & networkPriorityMask)
}

// IsExpectingReply reports whether the Expecting-Reply bit is set in the NPCI.
func (n *NetworkLayerProtocolDataUnit) IsExpectingReply() bool {
	return n.flags&expectingReplyMask != 0
}

// IsNetworkLayerMessage reports whether the NPDU carries a network layer message
// rather than a BACnet APDU.
func (n *NetworkLayerProtocolDataUnit) IsNetworkLayerMessage() bool {
	return n.flags&isNetworkLayerMessageMask != 0
}

// PayloadKind reports whether the NPDU carries application payload or a
// network-layer-message payload.
func (n *NetworkLayerProtocolDataUnit) PayloadKind() PayloadKind {
	if n.IsNetworkLayerMessage() {
		return PayloadKindNetworkLayerMessage
	}
	return PayloadKindApplication
}

// NPCI returns a typed view of the NPDU control and routing metadata.
func (n *NetworkLayerProtocolDataUnit) NPCI() NPCI {
	out := NPCI{
		Priority:       n.Priority(),
		ExpectingReply: n.IsExpectingReply(),
	}

	if n.HasDestinationSpecifier() && n.dnet != nil && n.hopCount != nil {
		dst := &DestinationSpecifier{DNET: *n.dnet, HopCount: *n.hopCount}
		if n.dadr != nil {
			dst.DADR = slices.Clone(n.dadr)
		}
		out.Destination = dst
	}

	if n.HasSourceSpecifier() && n.snet != nil {
		src := &SourceSpecifier{SNET: *n.snet}
		if n.sadr != nil {
			src.SADR = slices.Clone(n.sadr)
		}
		out.Source = src
	}

	return out
}

// HasDestinationSpecifier reports whether DNET/DLEN/DADR/HopCount fields are present.
func (n *NetworkLayerProtocolDataUnit) HasDestinationSpecifier() bool {
	return n.flags&destinationSpecifierMask != 0
}

// HasSourceSpecifier reports whether SNET/SLEN/SADR fields are present.
func (n *NetworkLayerProtocolDataUnit) HasSourceSpecifier() bool {
	return n.flags&sourceSpecifierMask != 0
}

// DNET returns the destination network number, or nil if the destination specifier is absent.
func (n *NetworkLayerProtocolDataUnit) DNET() *UltimateDestinationNetworkNumber {
	if n.dnet == nil {
		return nil
	}

	return ptr(*n.dnet)
}

// DADR returns a defensive copy of the destination MAC-layer address.
// Returns nil when the destination specifier is absent or DLEN is 0 (broadcast on DNET).
func (n *NetworkLayerProtocolDataUnit) DADR() UltimateDestinationMacLayerAddress {
	if n.dadr == nil {
		return nil
	}
	return slices.Clone(n.dadr)
}

// HopCount returns the hop count, or nil if the destination specifier is absent.
func (n *NetworkLayerProtocolDataUnit) HopCount() *uint8 {
	if n.hopCount == nil {
		return nil
	}
	return ptr(*n.hopCount)
}

// SNET returns the source network number, or nil if the source specifier is absent.
func (n *NetworkLayerProtocolDataUnit) SNET() *OriginalSourceNetworkNumber {
	if n.snet == nil {
		return nil
	}
	return ptr(*n.snet)
}

// SADR returns a defensive copy of the source MAC-layer address.
// Returns nil when the source specifier is absent.
func (n *NetworkLayerProtocolDataUnit) SADR() OriginalSourceMacLayerAddress {
	if n.sadr == nil {
		return nil
	}
	return slices.Clone(n.sadr)
}

// MessageType returns the network-layer message type byte, or nil if this NPDU
// does not carry a network layer message.
func (n *NetworkLayerProtocolDataUnit) MessageType() *uint8 {
	if n.messageType == nil {
		return nil
	}
	return ptr(*n.messageType)
}

// NetworkLayerHeader returns typed network-layer-message header metadata, or nil
// when this NPDU carries application payload.
func (n *NetworkLayerProtocolDataUnit) NetworkLayerHeader() *NetworkLayerMessageHeader {
	if n.messageType == nil || !n.IsNetworkLayerMessage() {
		return nil
	}
	h := NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(*n.messageType)}
	if n.vendorId != nil {
		h.VendorID = ptr(*n.vendorId)
	}
	return &h
}

// NetworkLayerMessageModel decodes the NPDU payload into a typed network-layer-message model.
// It returns nil,nil when the NPDU carries application payload.
func (n *NetworkLayerProtocolDataUnit) NetworkLayerMessageModel() (NetworkLayerMessageModel, error) {
	if n == nil {
		return nil, errors.NewValidationError("npdu", nil, ErrDecodeFailure)
	}
	if !n.IsNetworkLayerMessage() {
		return nil, nil
	}

	header := n.NetworkLayerHeader()
	if header == nil {
		return nil, errors.NewValidationError("network layer header", nil, ErrDecodeFailure)
	}

	return DecodeNetworkLayerMessageModel(*header, n.apdu)
}

// MustNetworkLayerMessageHeader returns a validated network-layer-message header from a typed model.
// It panics when message is nil, invalid, or yields an invalid header.
func MustNetworkLayerMessageHeader(message NetworkLayerMessageModel) NetworkLayerMessageHeader {
	if message == nil {
		panic("npdu: nil network-layer message model")
	}
	if !message.Valid() {
		panic("npdu: invalid network-layer message model")
	}

	header := message.Header()
	if !header.structureValid() {
		panic("npdu: invalid network-layer message header")
	}

	return header
}

// MustNetworkLayerMessageHeader returns a validated network-layer-message header from the NPDU.
// It panics when the NPDU does not carry a network-layer message or the header is invalid.
func (n *NetworkLayerProtocolDataUnit) MustNetworkLayerMessageHeader() NetworkLayerMessageHeader {
	header := n.NetworkLayerHeader()
	if header == nil {
		panic("npdu: network-layer message header is unavailable")
	}
	if !header.structureValid() {
		panic("npdu: invalid network-layer message header")
	}

	return *header
}

// VendorID returns the vendor ID for proprietary network layer messages, or nil if absent.
func (n *NetworkLayerProtocolDataUnit) VendorID() *uint16 {
	if n.vendorId == nil {
		return nil
	}
	return ptr(*n.vendorId)
}

// APDUBytes returns a defensive copy of the APDU or network-layer-message data payload.
func (n *NetworkLayerProtocolDataUnit) APDUBytes() []byte {
	if n.apdu == nil {
		return nil
	}
	return slices.Clone(n.apdu)
}

// ApplicationPayloadBytes returns a defensive copy of application payload bytes,
// or nil when the NPDU carries a network-layer message.
func (n *NetworkLayerProtocolDataUnit) ApplicationPayloadBytes() []byte {
	if n.IsNetworkLayerMessage() {
		return nil
	}
	return n.APDUBytes()
}

// NetworkLayerPayloadBytes returns a defensive copy of network-layer-message
// payload bytes, or nil when the NPDU carries application payload.
func (n *NetworkLayerProtocolDataUnit) NetworkLayerPayloadBytes() []byte {
	if !n.IsNetworkLayerMessage() {
		return nil
	}
	return n.APDUBytes()
}

// --- Types and constants ---

// NPCIFieldsFlags is the NPCI control byte (byte 2 of the NPDU wire format).
type NPCIFieldsFlags uint8

// Flag masks for the NPCI byte per clause 6.2.2, Table 6-1 of ANSI/ASHRAE 135-2024.
const (
	networkPriorityMask       NPCIFieldsFlags = 0b00000011 // bits 1-0: network priority
	expectingReplyMask        NPCIFieldsFlags = 0b00000100 // bit 2: expecting reply
	sourceSpecifierMask       NPCIFieldsFlags = 0b00001000 // bit 3: source specifier present
	reservedBit4Mask          NPCIFieldsFlags = 0b00010000 // bit 4: reserved (must be 0)
	destinationSpecifierMask  NPCIFieldsFlags = 0b00100000 // bit 5: destination specifier present
	reservedBit6Mask          NPCIFieldsFlags = 0b01000000 // bit 6: reserved (must be 0)
	isNetworkLayerMessageMask NPCIFieldsFlags = 0b10000000 // bit 7: network layer message
)

func (f NPCIFieldsFlags) String() string {
	return fmt.Sprintf("%b", f)
}

type UltimateDestinationNetworkNumber uint16
type UltimateDestinationNetworkNumberMacAddressLength uint8
type UltimateDestinationMacLayerAddress []byte
type LocalNetworkDestinationMacLayerAddress []byte
type OriginalSourceNetworkNumber uint16

func (snet OriginalSourceNetworkNumber) Valid() bool {
	return snet != OriginalSourceNetworkNumber(netprim.LocalNetwork) && snet != OriginalSourceNetworkNumber(netprim.GlobalBroadcastNetwork)
}

func (snet OriginalSourceNetworkNumber) ToBacnetNetworkNumber() netprim.NetworkNumber {
	return netprim.NetworkNumber(snet)
}

type OriginalSourceNetworkNumberMacAddressLength uint8
type OriginalSourceMacLayerAddress []byte
type LocalNetworkSourceMacLayerAddress []byte
