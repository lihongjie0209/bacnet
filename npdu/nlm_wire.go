package npdu

import (
	"encoding/binary"
	"fmt"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/log"
)

const minProprietaryNetworkLayerMessageWireLen = 3

// EncodeNetworkLayerMessageWire encodes a typed network-layer message to the
// BACnet wire format used inside an NPDU network-layer-message body:
// MessageType, optional VendorID for proprietary types, then payload bytes.
func EncodeNetworkLayerMessageWire(message NetworkLayerMessageModel) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: %v", ErrEncodeFailure, errors.NewValidationError("message", nil, ErrInvalidMessage))
	}
	if !message.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrEncodeFailure, errors.NewValidationError("message", message, ErrInvalidMessage))
	}

	header := message.Header()
	if !header.structureValid() {
		return nil, fmt.Errorf("%w: %v", ErrEncodeFailure, errors.NewValidationError("network layer message header", header, ErrInvalidMessage))
	}

	payload := message.PayloadBytes()
	length := 1 + len(payload)
	if header.VendorID != nil {
		length += 2
	}

	out := make([]byte, length)
	out[0] = byte(header.MessageType)
	offset := 1
	if header.VendorID != nil {
		binary.BigEndian.PutUint16(out[offset:], *header.VendorID)
		offset += 2
	}
	copy(out[offset:], payload)
	return out, nil
}

// DecodeNetworkLayerMessageWire decodes one BACnet network-layer message from
// MessageType, optional VendorID, and payload bytes.
func DecodeNetworkLayerMessageWire(raw []byte) (NetworkLayerMessageModel, error) {
	log.Logger.Debug("npdu decode network-layer message wire inbound", "bytes", len(raw))
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: raw network-layer message too short", ErrDecodeFailure)
	}

	header := NetworkLayerMessageHeader{MessageType: NetworkLayerMessageType(raw[0])}
	offset := 1
	if header.MessageType.IsProprietary() {
		if len(raw) < minProprietaryNetworkLayerMessageWireLen {
			return nil, fmt.Errorf("%w: truncated proprietary vendor-id", ErrDecodeFailure)
		}
		header.VendorID = ptr(binary.BigEndian.Uint16(raw[offset:]))
		offset += 2
	}

	message, err := DecodeNetworkLayerMessageModel(header, raw[offset:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}

	log.Logger.Debug(
		"npdu decode network-layer message wire success",
		"message_type", uint8(header.MessageType),
		"has_vendor_id", header.VendorID != nil,
		"payload_bytes", len(raw)-offset,
	)

	return message, nil
}
