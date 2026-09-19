package npdu

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/netprim"
)

// NetworkLayerMessageModel is a typed BACnet network-layer-message payload model.
//
// Implementations map to one NetworkLayerMessageType and own their payload bytes.
// PayloadBytes must return a defensive copy.
type NetworkLayerMessageModel interface {
	Header() NetworkLayerMessageHeader
	PayloadBytes() []byte
	Valid() bool
}

// RoutingTablePortEntry models one routing-table port info entry.
type RoutingTablePortEntry struct {
	connectedDNET netprim.NetworkNumber
	portID        uint8
	portInfo      []byte
}

func (e RoutingTablePortEntry) ConnectedDNET() netprim.NetworkNumber {
	return e.connectedDNET
}

func (e RoutingTablePortEntry) PortID() uint8 {
	return e.portID
}

func (e RoutingTablePortEntry) PortInfo() []byte {
	return slices.Clone(e.portInfo)
}

// NewRoutingTablePortEntry constructs a validated routing-table port entry.
func NewRoutingTablePortEntry(connectedDNET netprim.NetworkNumber, portID uint8, portInfo []byte) (RoutingTablePortEntry, error) {
	if connectedDNET.IsLocal() || connectedDNET.IsGlobalBroadcast() {
		return RoutingTablePortEntry{}, errors.NewValidationError("connected dnet", connectedDNET, ErrInvalidNetworkNumber)
	}

	if len(portInfo) > 255 {
		return RoutingTablePortEntry{}, errors.NewValidationError("port info", len(portInfo), ErrInvalidLength)
	}

	return RoutingTablePortEntry{
		connectedDNET: connectedDNET,
		portID:        portID,
		portInfo:      slices.Clone(portInfo),
	}, nil
}

func (e RoutingTablePortEntry) valid() bool {
	if e.connectedDNET.IsLocal() || e.connectedDNET.IsGlobalBroadcast() {
		return false
	}

	return len(e.portInfo) <= 255
}

func encodePortEntryList(ports []RoutingTablePortEntry) []byte {
	out := make([]byte, 1)
	out[0] = byte(len(ports))
	for _, p := range ports {
		out = append(out, byte(p.connectedDNET>>8), byte(p.connectedDNET), p.portID, byte(len(p.portInfo)))
		out = append(out, p.portInfo...)
	}
	return out
}

func encodeNetworkList(networks []netprim.NetworkNumber) ([]byte, error) {
	err := validateNetworkList(networks)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(networks)*2)
	for i, n := range networks {
		binary.BigEndian.PutUint16(out[i*2:], uint16(n))
	}

	return out, nil
}

func decodeNetworkList(payload []byte, requireAtLeastOne bool) ([]netprim.NetworkNumber, error) {
	if requireAtLeastOne && len(payload) == 0 {
		return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
	}

	if len(payload)%2 != 0 {
		return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
	}

	networks := make([]netprim.NetworkNumber, 0, len(payload)/2)
	for i := 0; i < len(payload); i += 2 {
		n := netprim.NetworkNumber(binary.BigEndian.Uint16(payload[i:]))
		networks = append(networks, n)
	}

	err := validateNetworkList(networks)
	if err != nil {
		return nil, err
	}

	return networks, nil
}

func validateNetworkList(networks []netprim.NetworkNumber) error {
	if len(networks) == 0 {
		return errors.NewValidationError("networks", len(networks), ErrInvalidLength)
	}

	for _, n := range networks {
		if n.IsLocal() || n.IsGlobalBroadcast() {
			return errors.NewValidationError("network", n, ErrInvalidNetworkNumber)
		}
	}

	return nil
}

// WhoIsRouterToNetworkMessage models who-is-router-to-network (0x00).
// DNET is optional; nil means "any network".
type WhoIsRouterToNetworkMessage struct {
	DNET *netprim.NetworkNumber
}

// NewWhoIsRouterToNetworkMessage constructs a who-is-router-to-network model.
func NewWhoIsRouterToNetworkMessage(dnet *netprim.NetworkNumber) (WhoIsRouterToNetworkMessage, error) {
	if dnet == nil {
		//DNET optional => missing not an error
		return WhoIsRouterToNetworkMessage{}, nil
	}

	if dnet.IsLocal() || dnet.IsGlobalBroadcast() {
		return WhoIsRouterToNetworkMessage{}, errors.NewValidationError("dnet", *dnet, ErrInvalidNetworkNumber)
	}

	return WhoIsRouterToNetworkMessage{DNET: ptr(*dnet)}, nil
}

func (m WhoIsRouterToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeWhoIsRouterToNetwork}
}

func (m WhoIsRouterToNetworkMessage) PayloadBytes() []byte {
	if m.DNET == nil {
		return nil
	}

	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(*m.DNET))
	return out
}

func (m WhoIsRouterToNetworkMessage) Valid() bool {
	if m.DNET == nil {
		return true
	}

	return !m.DNET.IsLocal() && !m.DNET.IsGlobalBroadcast()
}

// IAmRouterToNetworkMessage models i-am-router-to-network (0x01).
type IAmRouterToNetworkMessage struct {
	Networks []netprim.NetworkNumber
}

// NewIAmRouterToNetworkMessage constructs an i-am-router-to-network model.
func NewIAmRouterToNetworkMessage(networks []netprim.NetworkNumber) (IAmRouterToNetworkMessage, error) {
	copied := slices.Clone(networks)

	if err := validateNetworkList(copied); err != nil {
		return IAmRouterToNetworkMessage{}, err
	}

	return IAmRouterToNetworkMessage{Networks: copied}, nil
}

func (m IAmRouterToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeIAmRouterToNetwork}
}

func (m IAmRouterToNetworkMessage) PayloadBytes() []byte {
	out, _ := encodeNetworkList(m.Networks)
	return out
}

func (m IAmRouterToNetworkMessage) Valid() bool {
	return validateNetworkList(m.Networks) == nil
}

// RouterBusyToNetworkMessage models router-busy-to-network (0x04).
type RouterBusyToNetworkMessage struct {
	Networks []netprim.NetworkNumber
}

// NewRouterBusyToNetworkMessage constructs a router-busy-to-network model.
func NewRouterBusyToNetworkMessage(networks []netprim.NetworkNumber) (RouterBusyToNetworkMessage, error) {
	copied := append([]netprim.NetworkNumber(nil), networks...)
	if err := validateNetworkList(copied); err != nil {
		return RouterBusyToNetworkMessage{}, err
	}

	return RouterBusyToNetworkMessage{Networks: copied}, nil
}

func (m RouterBusyToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeRouterBusyToNetwork}
}

func (m RouterBusyToNetworkMessage) PayloadBytes() []byte {
	out, _ := encodeNetworkList(m.Networks)
	return out
}

func (m RouterBusyToNetworkMessage) Valid() bool {
	return validateNetworkList(m.Networks) == nil
}

// RouterAvailableToNetworkMessage models router-available-to-network (0x05).
type RouterAvailableToNetworkMessage struct {
	Networks []netprim.NetworkNumber
}

// NewRouterAvailableToNetworkMessage constructs a router-available-to-network model.
func NewRouterAvailableToNetworkMessage(networks []netprim.NetworkNumber) (RouterAvailableToNetworkMessage, error) {
	copied := append([]netprim.NetworkNumber(nil), networks...)
	if err := validateNetworkList(copied); err != nil {
		return RouterAvailableToNetworkMessage{}, err
	}

	return RouterAvailableToNetworkMessage{Networks: copied}, nil
}

func (m RouterAvailableToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeRouterAvailableToNetwork}
}

func (m RouterAvailableToNetworkMessage) PayloadBytes() []byte {
	out, _ := encodeNetworkList(m.Networks)
	return out
}

func (m RouterAvailableToNetworkMessage) Valid() bool {
	return validateNetworkList(m.Networks) == nil
}

// ICouldBeRouterToNetworkMessage models i-could-be-router-to-network (0x02).
type ICouldBeRouterToNetworkMessage struct {
	DNET             netprim.NetworkNumber
	PerformanceIndex uint8
}

// NewICouldBeRouterToNetworkMessage constructs an i-could-be-router-to-network model.
func NewICouldBeRouterToNetworkMessage(dnet netprim.NetworkNumber, performanceIndex uint8) (ICouldBeRouterToNetworkMessage, error) {
	if dnet.IsLocal() || dnet.IsGlobalBroadcast() {
		return ICouldBeRouterToNetworkMessage{}, errors.NewValidationError("dnet", dnet, ErrInvalidNetworkNumber)
	}
	return ICouldBeRouterToNetworkMessage{DNET: dnet, PerformanceIndex: performanceIndex}, nil
}

func (m ICouldBeRouterToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeICouldBeRouterToNetwork}
}

func (m ICouldBeRouterToNetworkMessage) PayloadBytes() []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, uint16(m.DNET))
	out[2] = m.PerformanceIndex
	return out
}

func (m ICouldBeRouterToNetworkMessage) Valid() bool {
	return !m.DNET.IsLocal() && !m.DNET.IsGlobalBroadcast()
}

// RejectMessageToNetworkMessage models reject-message-to-network (0x03).
type RejectMessageToNetworkMessage struct {
	DNET   netprim.NetworkNumber
	Reason NlmRejectReason
}

// NewRejectMessageToNetworkMessage constructs a reject-message-to-network model.
// reason must be a valid NLM reject reason per clause 6.6.4.
func NewRejectMessageToNetworkMessage(dnet netprim.NetworkNumber, reason NlmRejectReason) (RejectMessageToNetworkMessage, error) {
	if dnet.IsLocal() || dnet.IsGlobalBroadcast() {
		return RejectMessageToNetworkMessage{}, errors.NewValidationError("dnet", dnet, ErrInvalidNetworkNumber)
	}
	if !reason.ValidStandard() {
		return RejectMessageToNetworkMessage{}, errors.NewValidationError("reason", reason, ErrInvalidMessage)
	}
	return RejectMessageToNetworkMessage{DNET: dnet, Reason: reason}, nil
}

func (m RejectMessageToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeRejectMessageToNetwork}
}

func (m RejectMessageToNetworkMessage) PayloadBytes() []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, uint16(m.DNET))
	out[2] = byte(m.Reason)
	return out
}

func (m RejectMessageToNetworkMessage) Valid() bool {
	return !m.DNET.IsLocal() && m.Reason.ValidStandard()
}

// InitialiseRoutingTableMessage models initialise-routing-table (0x06).
type InitialiseRoutingTableMessage struct {
	Ports []RoutingTablePortEntry
}

// NewInitializeRoutingTableMessage constructs an initialise-routing-table model.
func NewInitializeRoutingTableMessage(ports []RoutingTablePortEntry) (InitialiseRoutingTableMessage, error) {
	copied := make([]RoutingTablePortEntry, len(ports))
	for i := range ports {
		if !ports[i].valid() {
			return InitialiseRoutingTableMessage{}, errors.NewValidationError("ports", i, ErrInvalidLength)
		}
		copied[i] = ports[i]
		copied[i].portInfo = slices.Clone(ports[i].portInfo)
	}
	return InitialiseRoutingTableMessage{Ports: copied}, nil
}

func (m InitialiseRoutingTableMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeInitializeRoutingTable}
}

func (m InitialiseRoutingTableMessage) PayloadBytes() []byte {
	return encodePortEntryList(m.Ports)
}

func (m InitialiseRoutingTableMessage) Valid() bool {
	if len(m.Ports) > 255 || len(m.Ports) == 0 {
		return false
	}

	for i := range m.Ports {
		if !m.Ports[i].valid() {
			return false
		}
	}

	return true
}

// InitialiseRoutingTableAckMessage models initialise-routing-table-ack (0x07).
type InitialiseRoutingTableAckMessage struct {
	Ports []RoutingTablePortEntry
}

// NewInitializeRoutingTableAckMessage constructs an initialise-routing-table-ack model.
func NewInitializeRoutingTableAckMessage(ports []RoutingTablePortEntry) (InitialiseRoutingTableAckMessage, error) {
	copied := make([]RoutingTablePortEntry, len(ports))
	for i := range ports {
		if !ports[i].valid() {
			return InitialiseRoutingTableAckMessage{}, errors.NewValidationError("ports", i, ErrInvalidLength)
		}
		copied[i] = ports[i]
		copied[i].portInfo = slices.Clone(ports[i].portInfo)
	}

	return InitialiseRoutingTableAckMessage{Ports: copied}, nil
}

func (m InitialiseRoutingTableAckMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeInitializeRoutingTableAck}
}

func (m InitialiseRoutingTableAckMessage) PayloadBytes() []byte {
	return encodePortEntryList(m.Ports)
}

func (m InitialiseRoutingTableAckMessage) Valid() bool {
	if len(m.Ports) > 255 || len(m.Ports) == 0 {
		return false
	}

	for i := range m.Ports {
		if !m.Ports[i].valid() {
			return false
		}
	}

	return true
}

// EstablishConnectionToNetworkMessage models establish-connection-to-network (0x08).
type EstablishConnectionToNetworkMessage struct {
	DNET            netprim.NetworkNumber
	TerminationTime uint8
}

// NewEstablishConnectionToNetworkMessage constructs an establish-connection-to-network model.
func NewEstablishConnectionToNetworkMessage(dnet netprim.NetworkNumber, terminationTime uint8) (EstablishConnectionToNetworkMessage, error) {
	if dnet.IsLocal() || dnet.IsGlobalBroadcast() {
		return EstablishConnectionToNetworkMessage{}, errors.NewValidationError("dnet", dnet, ErrInvalidNetworkNumber)
	}

	return EstablishConnectionToNetworkMessage{DNET: dnet, TerminationTime: terminationTime}, nil
}

func (m EstablishConnectionToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeEstablishConnectionToNetwork}
}

func (m EstablishConnectionToNetworkMessage) PayloadBytes() []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, uint16(m.DNET))
	out[2] = m.TerminationTime

	return out
}

func (m EstablishConnectionToNetworkMessage) Valid() bool {
	return !m.DNET.IsLocal() && !m.DNET.IsGlobalBroadcast()
}

// DisconnectConnectionToNetworkMessage models disconnect-connection-to-network (0x09).
type DisconnectConnectionToNetworkMessage struct {
	DNET netprim.NetworkNumber
}

// NewDisconnectConnectionToNetworkMessage constructs a disconnect-connection-to-network model.
func NewDisconnectConnectionToNetworkMessage(dnet netprim.NetworkNumber) (DisconnectConnectionToNetworkMessage, error) {
	if dnet.IsLocal() || dnet.IsGlobalBroadcast() {
		return DisconnectConnectionToNetworkMessage{}, errors.NewValidationError("dnet", dnet, ErrInvalidNetworkNumber)
	}

	return DisconnectConnectionToNetworkMessage{DNET: dnet}, nil
}

func (m DisconnectConnectionToNetworkMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeDisconnectConnectionToNetwork}
}

func (m DisconnectConnectionToNetworkMessage) PayloadBytes() []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(m.DNET))

	return out
}

func (m DisconnectConnectionToNetworkMessage) Valid() bool {
	return !m.DNET.IsLocal() && !m.DNET.IsGlobalBroadcast()
}

// WhatIsNetworkNumberMessage models what-is-network-number (0x12).
type WhatIsNetworkNumberMessage struct{}

// NewWhatIsNetworkNumberMessage constructs a what-is-network-number model.
func NewWhatIsNetworkNumberMessage() (WhatIsNetworkNumberMessage, error) {
	return WhatIsNetworkNumberMessage{}, nil
}

func (m WhatIsNetworkNumberMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeWhatIsNetworkNumber}
}

func (m WhatIsNetworkNumberMessage) PayloadBytes() []byte { return nil }

func (m WhatIsNetworkNumberMessage) Valid() bool { return true }

// NetworkNumberIsMessage models network-number-is (0x13).
type NetworkNumberIsMessage struct {
	NetworkNumber netprim.NetworkNumber
	Configured    bool
}

// NewNetworkNumberIsMessage constructs a network-number-is model.
func NewNetworkNumberIsMessage(networkNumber netprim.NetworkNumber, configured bool) (NetworkNumberIsMessage, error) {
	if networkNumber.IsLocal() || networkNumber.IsGlobalBroadcast() {
		return NetworkNumberIsMessage{}, errors.NewValidationError("network number", networkNumber, ErrInvalidNetworkNumber)
	}

	return NetworkNumberIsMessage{NetworkNumber: networkNumber, Configured: configured}, nil
}

func (m NetworkNumberIsMessage) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: NetworkLayerMessageTypeNetworkNumberIs}
}

func (m NetworkNumberIsMessage) PayloadBytes() []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, uint16(m.NetworkNumber))

	if m.Configured {
		out[2] = 0x01
	}

	return out
}

func (m NetworkNumberIsMessage) Valid() bool {
	return !m.NetworkNumber.IsLocal()
}

// ProprietaryNetworkLayerMessageModel models vendor proprietary network-layer messages.
type ProprietaryNetworkLayerMessageModel struct {
	MessageType NetworkLayerMessageType
	VendorID    uint16
	Payload     []byte
}

// NewProprietaryNetworkLayerMessageModel constructs a proprietary network-layer message model.
func NewProprietaryNetworkLayerMessageModel(messageType NetworkLayerMessageType, vendorID uint16, payload []byte) (ProprietaryNetworkLayerMessageModel, error) {
	if !messageType.IsProprietary() {
		return ProprietaryNetworkLayerMessageModel{}, errors.NewValidationError("message type", messageType, ErrInvalidMessage)
	}
	return ProprietaryNetworkLayerMessageModel{
		MessageType: messageType,
		VendorID:    vendorID,
		Payload:     slices.Clone(payload),
	}, nil
}

func (m ProprietaryNetworkLayerMessageModel) Header() NetworkLayerMessageHeader {
	return NetworkLayerMessageHeader{MessageType: m.MessageType, VendorID: ptr(m.VendorID)}
}

func (m ProprietaryNetworkLayerMessageModel) PayloadBytes() []byte {
	return slices.Clone(m.Payload)
}

func (m ProprietaryNetworkLayerMessageModel) Valid() bool {
	return m.MessageType.IsProprietary()
}

func decodeRoutingTableEntries(payload []byte) ([]RoutingTablePortEntry, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: routing-table payload missing number-of-ports", ErrInvalidLength)
	}

	portCount := int(payload[0])
	cursor := 1
	ports := make([]RoutingTablePortEntry, 0, portCount)

	for i := 0; i < portCount; i++ {
		if cursor+4 > len(payload) {
			return nil, fmt.Errorf("%w: routing-table payload truncated in port entry header %d", ErrInvalidLength, i)
		}
		connectedDNET := netprim.NetworkNumber(binary.BigEndian.Uint16(payload[cursor:]))
		if connectedDNET.IsLocal() || connectedDNET.IsGlobalBroadcast() {
			return nil, errors.NewValidationError("connected dnet", connectedDNET, ErrInvalidNetworkNumber)
		}

		portID := payload[cursor+2]
		portInfoLength := int(payload[cursor+3])
		cursor += 4
		if cursor+portInfoLength > len(payload) {
			return nil, fmt.Errorf("%w: routing-table payload truncated in port entry info %d", ErrInvalidLength, i)
		}
		entry, err := NewRoutingTablePortEntry(connectedDNET, portID, payload[cursor:cursor+portInfoLength])
		if err != nil {
			return nil, err
		}
		ports = append(ports, entry)
		cursor += portInfoLength
	}

	if cursor != len(payload) {
		return nil, fmt.Errorf("%w: routing-table payload has trailing bytes", ErrInvalidLength)
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("%w: routing-table payload has zero ports", ErrInvalidLength)
	}

	return ports, nil
}

// DecodeNetworkLayerMessageModel decodes a typed model from header and payload.
func DecodeNetworkLayerMessageModel(header NetworkLayerMessageHeader, payload []byte) (NetworkLayerMessageModel, error) {
	if !header.structureValid() {
		return nil, errors.NewValidationError("network layer message header", header, ErrInvalidMessage)
	}

	messageType := header.MessageType
	if messageType.IsProprietary() {
		if header.VendorID == nil {
			return nil, errors.NewValidationError("vendor id", nil, ErrInvalidMessage)
		}
		return NewProprietaryNetworkLayerMessageModel(messageType, *header.VendorID, payload)
	}

	if messageType.IsReserved() || !messageType.ValidStandard() {
		return nil, errors.NewValidationError("message type", messageType, ErrInvalidMessage)
	}

	switch messageType {
	case NetworkLayerMessageTypeWhoIsRouterToNetwork: // Goland gives an "is always false warning" this is a false
		// warning, since messageType on some paths is taken directly from wire bytes (and 0x00 is completely valid)
		switch len(payload) {
		case 0:
			return NewWhoIsRouterToNetworkMessage(nil)
		case 2:
			return NewWhoIsRouterToNetworkMessage(ptr(netprim.NetworkNumber(binary.BigEndian.Uint16(payload))))
		default:
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
	case NetworkLayerMessageTypeIAmRouterToNetwork:
		networks, err := decodeNetworkList(payload, true)
		if err != nil {
			return nil, err
		}
		return NewIAmRouterToNetworkMessage(networks)
	case NetworkLayerMessageTypeRouterBusyToNetwork:
		networks, err := decodeNetworkList(payload, true)
		if err != nil {
			return nil, err
		}
		return NewRouterBusyToNetworkMessage(networks)
	case NetworkLayerMessageTypeRouterAvailableToNetwork:
		networks, err := decodeNetworkList(payload, true)
		if err != nil {
			return nil, err
		}
		return NewRouterAvailableToNetworkMessage(networks)
	case NetworkLayerMessageTypeICouldBeRouterToNetwork:
		if len(payload) != 3 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		return NewICouldBeRouterToNetworkMessage(netprim.NetworkNumber(binary.BigEndian.Uint16(payload)), payload[2])
	case NetworkLayerMessageTypeRejectMessageToNetwork:
		if len(payload) != 3 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		return NewRejectMessageToNetworkMessage(netprim.NetworkNumber(binary.BigEndian.Uint16(payload)), NlmRejectReason(payload[2]))
	case NetworkLayerMessageTypeInitializeRoutingTable:
		ports, err := decodeRoutingTableEntries(payload)
		if err != nil {
			return nil, err
		}
		return NewInitializeRoutingTableMessage(ports)
	case NetworkLayerMessageTypeInitializeRoutingTableAck:
		ports, err := decodeRoutingTableEntries(payload)
		if err != nil {
			return nil, err
		}
		return NewInitializeRoutingTableAckMessage(ports)
	case NetworkLayerMessageTypeEstablishConnectionToNetwork:
		if len(payload) != 3 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		return NewEstablishConnectionToNetworkMessage(netprim.NetworkNumber(binary.BigEndian.Uint16(payload)), payload[2])
	case NetworkLayerMessageTypeDisconnectConnectionToNetwork:
		if len(payload) != 2 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		return NewDisconnectConnectionToNetworkMessage(netprim.NetworkNumber(binary.BigEndian.Uint16(payload)))
	case NetworkLayerMessageTypeWhatIsNetworkNumber:
		if len(payload) != 0 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		return NewWhatIsNetworkNumberMessage()
	case NetworkLayerMessageTypeNetworkNumberIs:
		if len(payload) != 3 {
			return nil, errors.NewValidationError("payload", len(payload), ErrInvalidLength)
		}
		configured := false
		if payload[2] == 0x01 {
			configured = true
		} else if payload[2] != 0x00 {
			return nil, errors.NewValidationError("network-number-is flag", payload[2], ErrInvalidMessage)
		}
		return NewNetworkNumberIsMessage(netprim.NetworkNumber(binary.BigEndian.Uint16(payload)), configured)
	default:
		return nil, errors.NewValidationError("message type", messageType, ErrInvalidMessage)
	}
}
