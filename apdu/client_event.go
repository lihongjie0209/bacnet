package apdu

import (
	"context"
	"fmt"
	"slices"
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

// EventNotificationIndication is the common confirmed/unconfirmed event body.
// RawParameters contains the exact encoded BACnetNotificationParameters choice,
// including its event-type opening and closing tags.
type EventNotificationIndication struct {
	Source                     netprim.Address
	ProcessIdentifier          uint32
	InitiatingDeviceIdentifier types.ObjectIdentifier
	EventObjectIdentifier      types.ObjectIdentifier
	Timestamp                  Timestamp
	NotificationClass          uint32
	Priority                   uint8
	EventType                  uint32
	MessageText                *string
	NotifyType                 uint32
	AckRequired                bool
	FromState                  *EventState
	ToState                    EventState
	RawParameters              []byte
}

type UnconfirmedEventNotificationHandler func(context.Context, EventNotificationIndication) error
type ConfirmedEventNotificationHandler func(context.Context, EventNotificationIndication) error

func (c *clientImpl) HandleConfirmedEventNotification(handler ConfirmedEventNotificationHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}
	return c.ue.HandleConfirmed(ServiceChoiceConfirmedEventNotification, func(ctx context.Context, indication ConfirmedIndicationICI) (ConfirmedResponseICI, error) {
		decoded, err := decodeEventNotificationPayload(indication.ServiceRequest.Payload)
		if err != nil {
			return ConfirmedResponseICI{}, err
		}
		decoded.Source = indication.Source
		if err := handler(ctx, decoded); err != nil {
			return ConfirmedResponseICI{}, err
		}
		return ConfirmedResponseICI{Destination: indication.Source, InvokeID: indication.InvokeID, ServiceResponse: ServiceResult{}}, nil
	})
}

func (c *clientImpl) HandleUnconfirmedEventNotification(handler UnconfirmedEventNotificationHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}
	return c.ue.HandleUnconfirmed(ServiceChoiceUnconfirmedEventNotification, func(ctx context.Context, indication UnconfirmedIndicationICI) error {
		decoded, err := decodeEventNotificationPayload(indication.ServiceRequest.Payload)
		if err != nil {
			return err
		}
		decoded.Source = indication.Source
		return handler(ctx, decoded)
	})
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

func decodeEventNotificationPayload(payload []byte) (EventNotificationIndication, error) {
	var out EventNotificationIndication
	offset := 0
	readUnsigned := func(tag bacencoding.AppTag) (uint32, error) {
		_, raw, next, err := bacencoding.DecodeExpectedContextPrimitive(payload, offset, tag)
		if err != nil {
			return 0, err
		}
		value, err := bacencoding.DecodeUnsigned(raw)
		if err == nil {
			offset = next
		}
		return value, err
	}
	var err error
	if out.ProcessIdentifier, err = readUnsigned(0); err != nil {
		return EventNotificationIndication{}, err
	}
	if out.ProcessIdentifier == 0 {
		return EventNotificationIndication{}, fmt.Errorf("%w: zero event process identifier", ErrDecodeFailure)
	}
	for tag, target := range []struct {
		tag bacencoding.AppTag
		out *types.ObjectIdentifier
	}{{1, &out.InitiatingDeviceIdentifier}, {2, &out.EventObjectIdentifier}} {
		_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, target.tag)
		if decodeErr != nil {
			return EventNotificationIndication{}, decodeErr
		}
		*target.out, decodeErr = bacencoding.DecodeObjectIdentifierValue(raw)
		if decodeErr != nil || !target.out.ObjectType().Valid() {
			return EventNotificationIndication{}, fmt.Errorf("%w: invalid event object at index %d", ErrDecodeFailure, tag)
		}
		offset = next
	}
	out.Timestamp, offset, err = decodeContextTimestamp(payload, offset, 3)
	if err != nil {
		return EventNotificationIndication{}, err
	}
	if out.NotificationClass, err = readUnsigned(4); err != nil {
		return EventNotificationIndication{}, err
	}
	priority, err := readUnsigned(5)
	if err != nil || priority > 255 {
		return EventNotificationIndication{}, fmt.Errorf("%w: invalid event priority", ErrDecodeFailure)
	}
	out.Priority = uint8(priority)
	if out.EventType, err = readUnsigned(6); err != nil || out.EventType > 65535 {
		return EventNotificationIndication{}, fmt.Errorf("%w: invalid event type", ErrDecodeFailure)
	}
	if hasContextPrimitive(payload, offset, 7) {
		_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, 7)
		if decodeErr != nil {
			return EventNotificationIndication{}, decodeErr
		}
		text, decodeErr := bacencoding.DecodeCharacterStringValue(raw)
		if decodeErr != nil || len(raw) > 256 {
			return EventNotificationIndication{}, fmt.Errorf("%w: invalid event message text", ErrDecodeFailure)
		}
		out.MessageText, offset = &text, next
	}
	if out.NotifyType, err = readUnsigned(8); err != nil || out.NotifyType > 2 {
		return EventNotificationIndication{}, fmt.Errorf("%w: invalid notify type %d: %v", ErrDecodeFailure, out.NotifyType, err)
	}
	if out.NotifyType <= 1 {
		if hasContextPrimitive(payload, offset, 9) {
			_, raw, next, decodeErr := bacencoding.DecodeExpectedContextPrimitive(payload, offset, 9)
			if decodeErr != nil || len(raw) != 1 || raw[0] > 1 {
				return EventNotificationIndication{}, fmt.Errorf("%w: invalid ack-required", ErrDecodeFailure)
			}
			out.AckRequired, offset = raw[0] == 1, next
		}
		if hasContextPrimitive(payload, offset, 10) {
			state, decodeErr := readUnsigned(10)
			if decodeErr != nil || state > uint32(EventStateLifeSafetyAlarm) {
				return EventNotificationIndication{}, fmt.Errorf("%w: invalid from-state", ErrDecodeFailure)
			}
			value := EventState(state)
			out.FromState = &value
		}
	}
	toState, err := readUnsigned(11)
	if err != nil || toState > uint32(EventStateLifeSafetyAlarm) {
		return EventNotificationIndication{}, fmt.Errorf("%w: invalid to-state", ErrDecodeFailure)
	}
	out.ToState = EventState(toState)
	if out.NotifyType <= 1 {
		contentStart, contentEnd, next, decodeErr := decodeConstructedContent(payload, offset, 12)
		if decodeErr != nil {
			return EventNotificationIndication{}, decodeErr
		}
		if contentStart == contentEnd {
			return EventNotificationIndication{}, fmt.Errorf("%w: empty event parameters", ErrDecodeFailure)
		}
		choice, _, _, decodeErr := bacencoding.ParseTag(payload[contentStart:contentEnd])
		if decodeErr != nil || !choice.Opening || (out.EventType < 64 && uint32(choice.TagNumber) != out.EventType) {
			return EventNotificationIndication{}, fmt.Errorf("%w: event parameter choice mismatch", ErrDecodeFailure)
		}
		out.RawParameters = slices.Clone(payload[contentStart:contentEnd])
		offset = next
	}
	if offset != len(payload) {
		return EventNotificationIndication{}, fmt.Errorf("%w: trailing event notification bytes", ErrDecodeFailure)
	}
	return out, nil
}

func hasContextPrimitive(payload []byte, offset int, expected bacencoding.AppTag) bool {
	if offset >= len(payload) {
		return false
	}
	tag, _, _, err := bacencoding.ParseTag(payload[offset:])
	return err == nil && tag.ContextSpecific && !tag.Opening && !tag.Closing && tag.TagNumber == expected
}

func decodeConstructedContent(payload []byte, offset int, expected bacencoding.AppTag) (int, int, int, error) {
	contentStart, err := bacencoding.ExpectOpeningTag(payload, offset, expected)
	if err != nil {
		return offset, offset, offset, err
	}
	stack := []bacencoding.AppTag{expected}
	position := contentStart
	for position < len(payload) {
		tag, header, valueLength, parseErr := bacencoding.ParseTag(payload[position:])
		if parseErr != nil {
			return offset, offset, offset, parseErr
		}
		if tag.Opening {
			stack = append(stack, tag.TagNumber)
			position += header
			continue
		}
		if tag.Closing {
			if len(stack) == 0 || stack[len(stack)-1] != tag.TagNumber {
				return offset, offset, offset, fmt.Errorf("%w: mismatched closing tag %d", ErrDecodeFailure, tag.TagNumber)
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return contentStart, position, position + header, nil
			}
			position += header
			continue
		}
		position += header + valueLength
	}
	return offset, offset, offset, fmt.Errorf("%w: unterminated constructed tag %d", ErrDecodeFailure, expected)
}
