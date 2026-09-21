package apdu

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

// EventState is the BACnet event-state enumeration.
type EventState uint32

const (
	EventStateNormal EventState = iota
	EventStateFault
	EventStateOffnormal
	EventStateHighLimit
	EventStateLowLimit
	EventStateLifeSafetyAlarm
)

// TimestampKind selects one BACnetTimeStamp choice.
type TimestampKind uint8

const (
	TimestampTime TimestampKind = iota
	TimestampSequence
	TimestampDateTime
)

// Timestamp preserves each standard BACnetTimeStamp choice without converting
// sequence numbers or local BACnet date/time fields to wall-clock time.
type Timestamp struct {
	Kind     TimestampKind
	Time     bacencoding.BACnetTime
	Sequence uint16
	DateTime bacencoding.BACnetDateTime
}

// AcknowledgeAlarmRequest is the typed AcknowledgeAlarm service payload.
type AcknowledgeAlarmRequest struct {
	ProcessIdentifier        uint32
	EventObjectIdentifier    types.ObjectIdentifier
	EventStateAcknowledged   EventState
	EventTimestamp           Timestamp
	AcknowledgementSource    string
	AcknowledgementTimestamp Timestamp
}

// GetEventInformationRequest optionally continues after the last object from a
// previous response page.
type GetEventInformationRequest struct {
	LastReceivedObjectIdentifier *types.ObjectIdentifier
}

// EventSummary is one GetEventInformation result entry. Transition bit order
// is to-offnormal, to-fault, to-normal.
type EventSummary struct {
	ObjectIdentifier        types.ObjectIdentifier
	EventState              EventState
	AcknowledgedTransitions bacencoding.BitString
	EventTimestamps         [3]Timestamp
	NotifyType              uint32
	EventEnable             bacencoding.BitString
	EventPriorities         [3]uint32
}

// GetEventInformationACK is one bounded protocol page.
type GetEventInformationACK struct {
	Events     []EventSummary
	MoreEvents bool
}

// GetEventInformation requests one page and strictly decodes its ComplexACK.
func (c *clientImpl) GetEventInformation(ctx context.Context, dst netprim.Address, req GetEventInformationRequest) (GetEventInformationACK, error) {
	payload := []byte(nil)
	if req.LastReceivedObjectIdentifier != nil {
		if !req.LastReceivedObjectIdentifier.ObjectType().Valid() {
			return GetEventInformationACK{}, errors.NewValidationError("last received object identifier", *req.LastReceivedObjectIdentifier, ErrEncodeFailure)
		}
		payload = bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeObjectIdentifierValue(*req.LastReceivedObjectIdentifier))
	}
	ackPayload, err := c.invokeConfirmedRawServiceChoice(ctx, dst, ServiceChoiceGetEventInformation, payload)
	if err != nil {
		return GetEventInformationACK{}, err
	}
	return decodeGetEventInformationACK(ackPayload, 65536)
}

// AcknowledgeAlarm sends service choice 0 and requires an empty SimpleACK.
func (c *clientImpl) AcknowledgeAlarm(ctx context.Context, dst netprim.Address, req AcknowledgeAlarmRequest) error {
	payload, err := encodeAcknowledgeAlarmRequest(req)
	if err != nil {
		return err
	}
	ackPayload, err := c.invokeConfirmedRawServiceChoice(ctx, dst, ServiceChoiceAcknowledgeAlarm, payload)
	if err != nil {
		return err
	}
	if len(ackPayload) != 0 {
		return fmt.Errorf("%w: acknowledge-alarm expected simple-ack payload to be empty", ErrDecodeFailure)
	}
	return nil
}

func encodeAcknowledgeAlarmRequest(req AcknowledgeAlarmRequest) ([]byte, error) {
	if req.ProcessIdentifier == 0 {
		return nil, errors.NewValidationError("process identifier", req.ProcessIdentifier, ErrEncodeFailure)
	}
	if !req.EventObjectIdentifier.ObjectType().Valid() {
		return nil, errors.NewValidationError("event object identifier", req.EventObjectIdentifier, ErrEncodeFailure)
	}
	if req.EventStateAcknowledged > EventStateLifeSafetyAlarm {
		return nil, errors.NewValidationError("event state", req.EventStateAcknowledged, ErrEncodeFailure)
	}
	if req.AcknowledgementSource == "" || !utf8.ValidString(req.AcknowledgementSource) || len(req.AcknowledgementSource) > 255 {
		return nil, errors.NewValidationError("acknowledgement source", req.AcknowledgementSource, ErrEncodeFailure)
	}
	eventTimestamp, err := encodeContextTimestamp(3, req.EventTimestamp)
	if err != nil {
		return nil, fmt.Errorf("event timestamp: %w", err)
	}
	source, err := bacencoding.EncodeCharacterStringValue(req.AcknowledgementSource)
	if err != nil {
		return nil, fmt.Errorf("acknowledgement source: %w", err)
	}
	ackTimestamp, err := encodeContextTimestamp(5, req.AcknowledgementTimestamp)
	if err != nil {
		return nil, fmt.Errorf("acknowledgement timestamp: %w", err)
	}
	out := make([]byte, 0, 64+len(source))
	out = append(out, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeUnsigned(req.ProcessIdentifier))...)
	out = append(out, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeObjectIdentifierValue(req.EventObjectIdentifier))...)
	out = append(out, bacencoding.EncodeContextPrimitive(2, bacencoding.EncodeEnumeratedValue(uint32(req.EventStateAcknowledged)))...)
	out = append(out, eventTimestamp...)
	out = append(out, bacencoding.EncodeContextPrimitive(4, source)...)
	out = append(out, ackTimestamp...)
	return out, nil
}

func encodeContextTimestamp(tag uint8, timestamp Timestamp) ([]byte, error) {
	inner := make([]byte, 0, 16)
	switch timestamp.Kind {
	case TimestampTime:
		inner = append(inner, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeTimeValue(timestamp.Time))...)
	case TimestampSequence:
		inner = append(inner, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeUnsigned(uint32(timestamp.Sequence)))...)
	case TimestampDateTime:
		dateTime, err := bacencoding.EncodeDateTimeValue(timestamp.DateTime)
		if err != nil {
			return nil, err
		}
		inner = append(inner, bacencoding.EncodeOpeningTag(2)...)
		inner = append(inner, dateTime...)
		inner = append(inner, bacencoding.EncodeClosingTag(2)...)
	default:
		return nil, errors.NewValidationError("timestamp kind", timestamp.Kind, ErrEncodeFailure)
	}
	out := bacencoding.EncodeOpeningTag(tag)
	out = append(out, inner...)
	out = append(out, bacencoding.EncodeClosingTag(tag)...)
	return out, nil
}

func decodeContextTimestamp(payload []byte, offset int, tag uint8) (Timestamp, int, error) {
	offset, err := bacencoding.ExpectOpeningTag(payload, offset, bacencoding.AppTag(tag))
	if err != nil {
		return Timestamp{}, offset, err
	}
	if offset >= len(payload) {
		return Timestamp{}, offset, fmt.Errorf("%w: missing timestamp choice", ErrDecodeFailure)
	}
	choice, _, _, err := bacencoding.ParseTag(payload[offset:])
	if err != nil || !choice.ContextSpecific || choice.Opening && choice.TagNumber != 2 {
		return Timestamp{}, offset, fmt.Errorf("%w: invalid timestamp choice", ErrDecodeFailure)
	}
	var timestamp Timestamp
	switch choice.TagNumber {
	case 0:
		_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, 0)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		timestamp.Kind = TimestampTime
		timestamp.Time, err = bacencoding.DecodeTimeValue(raw)
		offset = next
	case 1:
		_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, 1)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		value, decodeErr := bacencoding.DecodeUnsigned(raw)
		if decodeErr != nil || value > 65535 {
			return Timestamp{}, offset, fmt.Errorf("%w: invalid timestamp sequence", ErrDecodeFailure)
		}
		timestamp.Kind, timestamp.Sequence, offset = TimestampSequence, uint16(value), next
	case 2:
		var next int
		next, err = bacencoding.ExpectOpeningTag(payload, offset, 2)
		if err != nil {
			return Timestamp{}, offset, err
		}
		_, dateRaw, afterDate, decodeErr := bacencoding.DecodeExpectedApplicationPrimitive(payload, next, bacencoding.AppTagDate)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		_, timeRaw, afterTime, decodeErr := bacencoding.DecodeExpectedApplicationPrimitive(payload, afterDate, bacencoding.AppTagTime)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		date, decodeErr := bacencoding.DecodeDateValue(dateRaw)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		clock, decodeErr := bacencoding.DecodeTimeValue(timeRaw)
		if decodeErr != nil {
			return Timestamp{}, offset, decodeErr
		}
		offset, err = bacencoding.ExpectClosingTag(payload, afterTime, 2)
		timestamp = Timestamp{Kind: TimestampDateTime, DateTime: bacencoding.BACnetDateTime{Date: date, Time: clock}}
	default:
		return Timestamp{}, offset, fmt.Errorf("%w: unknown timestamp choice %d", ErrDecodeFailure, choice.TagNumber)
	}
	if err != nil {
		return Timestamp{}, offset, err
	}
	offset, err = bacencoding.ExpectClosingTag(payload, offset, bacencoding.AppTag(tag))
	return timestamp, offset, err
}

func decodeGetEventInformationACK(payload []byte, maxEvents int) (GetEventInformationACK, error) {
	if maxEvents < 1 {
		return GetEventInformationACK{}, errors.NewValidationError("max events", maxEvents, ErrDecodeFailure)
	}
	offset, err := bacencoding.ExpectOpeningTag(payload, 0, 0)
	if err != nil {
		return GetEventInformationACK{}, err
	}
	out := GetEventInformationACK{Events: make([]EventSummary, 0)}
	for {
		if offset >= len(payload) {
			return GetEventInformationACK{}, fmt.Errorf("%w: unterminated event summary list", ErrDecodeFailure)
		}
		tag, _, _, parseErr := bacencoding.ParseTag(payload[offset:])
		if parseErr != nil {
			return GetEventInformationACK{}, parseErr
		}
		if tag.Closing && tag.TagNumber == 0 {
			offset, err = bacencoding.ExpectClosingTag(payload, offset, 0)
			break
		}
		if len(out.Events) >= maxEvents {
			return GetEventInformationACK{}, fmt.Errorf("%w: event summary limit exceeded", ErrDecodeFailure)
		}
		var summary EventSummary
		_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, 0)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		summary.ObjectIdentifier, decodeErr = bacencoding.DecodeObjectIdentifierValue(raw)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		_, raw, next, decodeErr = bacencoding.DecodeExpectedContextPrimitive(payload, next, 1)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		state, decodeErr := bacencoding.DecodeEnumeratedValue(raw)
		if decodeErr != nil || state > uint32(EventStateLifeSafetyAlarm) {
			return GetEventInformationACK{}, fmt.Errorf("%w: invalid event state", ErrDecodeFailure)
		}
		summary.EventState = EventState(state)
		_, raw, next, decodeErr = bacencoding.DecodeExpectedContextPrimitive(payload, next, 2)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		summary.AcknowledgedTransitions, decodeErr = bacencoding.DecodeBitStringValue(raw)
		if decodeErr != nil || len(summary.AcknowledgedTransitions.Bits) != 3 {
			return GetEventInformationACK{}, fmt.Errorf("%w: acknowledged transitions must contain 3 bits", ErrDecodeFailure)
		}
		next, decodeErr = bacencoding.ExpectOpeningTag(payload, next, 3)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		for i := range summary.EventTimestamps {
			summary.EventTimestamps[i], next, decodeErr = decodeBareTimestamp(payload, next)
			if decodeErr != nil {
				return GetEventInformationACK{}, decodeErr
			}
		}
		next, decodeErr = bacencoding.ExpectClosingTag(payload, next, 3)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		_, raw, next, decodeErr = bacencoding.DecodeExpectedContextPrimitive(payload, next, 4)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		summary.NotifyType, decodeErr = bacencoding.DecodeEnumeratedValue(raw)
		if decodeErr != nil || summary.NotifyType > 2 {
			return GetEventInformationACK{}, fmt.Errorf("%w: invalid notify type", ErrDecodeFailure)
		}
		_, raw, next, decodeErr = bacencoding.DecodeExpectedContextPrimitive(payload, next, 5)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		summary.EventEnable, decodeErr = bacencoding.DecodeBitStringValue(raw)
		if decodeErr != nil || len(summary.EventEnable.Bits) != 3 {
			return GetEventInformationACK{}, fmt.Errorf("%w: event enable must contain 3 bits", ErrDecodeFailure)
		}
		next, decodeErr = bacencoding.ExpectOpeningTag(payload, next, 6)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		for i := range summary.EventPriorities {
			_, raw, next, decodeErr = bacencoding.DecodeExpectedApplicationPrimitive(payload, next, bacencoding.AppTagUnsignedInteger)
			if decodeErr != nil {
				return GetEventInformationACK{}, decodeErr
			}
			summary.EventPriorities[i], decodeErr = bacencoding.DecodeUnsigned(raw)
			if decodeErr != nil || summary.EventPriorities[i] > 255 {
				return GetEventInformationACK{}, fmt.Errorf("%w: invalid event priority", ErrDecodeFailure)
			}
		}
		offset, decodeErr = bacencoding.ExpectClosingTag(payload, next, 6)
		if decodeErr != nil {
			return GetEventInformationACK{}, decodeErr
		}
		out.Events = append(out.Events, summary)
	}
	var raw []byte
	_, raw, offset, err = bacencoding.DecodeExpectedContextPrimitive(payload, offset, 1)
	if err != nil || len(raw) != 1 || raw[0] > 1 || offset != len(payload) {
		return GetEventInformationACK{}, fmt.Errorf("%w: invalid more-events or trailing bytes", ErrDecodeFailure)
	}
	out.MoreEvents = raw[0] == 1
	return out, nil
}

func decodeBareTimestamp(payload []byte, offset int) (Timestamp, int, error) {
	if offset >= len(payload) {
		return Timestamp{}, offset, fmt.Errorf("%w: missing timestamp", ErrDecodeFailure)
	}
	tag, _, _, err := bacencoding.ParseTag(payload[offset:])
	if err != nil || !tag.ContextSpecific {
		return Timestamp{}, offset, fmt.Errorf("%w: invalid timestamp", ErrDecodeFailure)
	}
	wrapped := append(bacencoding.EncodeOpeningTag(7), payload[offset:]...)
	// Find exactly one choice by decoding it under a synthetic outer tag. The
	// consumed size excludes the synthetic opening/closing headers.
	choiceStart := len(bacencoding.EncodeOpeningTag(7))
	var choiceEnd int
	switch tag.TagNumber {
	case 0, 1:
		_, _, choiceEnd, err = bacencoding.DecodeExpectedContextPrimitive(wrapped, choiceStart, tag.TagNumber)
	case 2:
		choiceEnd, err = bacencoding.ExpectOpeningTag(wrapped, choiceStart, 2)
		if err == nil {
			_, _, choiceEnd, err = bacencoding.DecodeExpectedApplicationPrimitive(wrapped, choiceEnd, bacencoding.AppTagDate)
		}
		if err == nil {
			_, _, choiceEnd, err = bacencoding.DecodeExpectedApplicationPrimitive(wrapped, choiceEnd, bacencoding.AppTagTime)
		}
		if err == nil {
			choiceEnd, err = bacencoding.ExpectClosingTag(wrapped, choiceEnd, 2)
		}
	default:
		err = fmt.Errorf("%w: unknown timestamp choice", ErrDecodeFailure)
	}
	if err != nil {
		return Timestamp{}, offset, err
	}
	wrapped = append(wrapped[:choiceEnd], bacencoding.EncodeClosingTag(7)...)
	decoded, _, err := decodeContextTimestamp(wrapped, 0, 7)
	return decoded, offset + choiceEnd - choiceStart, err
}
