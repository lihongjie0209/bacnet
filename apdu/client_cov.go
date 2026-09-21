package apdu

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

// SubscriberProcessIdentifier identifies a client-local COV subscription process.
type SubscriberProcessIdentifier uint32

// COVLifetime is the requested subscription lifetime in seconds.
type COVLifetime uint32

// COVIncrement is the optional increment threshold for SubscribeCOVProperty.
type COVIncrement float32

// MonitoredPropertyReference identifies one monitored property and optional array index.
type MonitoredPropertyReference struct {
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
}

// SubscribeCOVRequest is the typed request payload for SubscribeCOV.
type SubscribeCOVRequest struct {
	SubscriberProcessIdentifier SubscriberProcessIdentifier
	MonitoredObjectIdentifier   types.ObjectIdentifier
	IssueConfirmedNotifications *bool
	Lifetime                    *COVLifetime
}

// NewSubscribeCOVRequest constructs a validated SubscribeCOVRequest.
func NewSubscribeCOVRequest(
	subscriberProcessIdentifier SubscriberProcessIdentifier,
	monitoredObjectIdentifier types.ObjectIdentifier,
	issueConfirmedNotifications *bool,
	lifetime *COVLifetime,
) (SubscribeCOVRequest, error) {
	req := SubscribeCOVRequest{
		SubscriberProcessIdentifier: subscriberProcessIdentifier,
		MonitoredObjectIdentifier:   monitoredObjectIdentifier,
		IssueConfirmedNotifications: issueConfirmedNotifications,
		Lifetime:                    lifetime,
	}
	if err := validateSubscribeCOVRequest(req); err != nil {
		return SubscribeCOVRequest{}, err
	}
	return req, nil
}

func validateSubscribeCOVRequest(req SubscribeCOVRequest) error {
	if !req.MonitoredObjectIdentifier.ObjectType().Valid() {
		return errors.NewValidationError("monitored object identifier", req.MonitoredObjectIdentifier, ErrEncodeFailure)
	}
	return nil
}

func (c *clientImpl) SubscribeCOV(ctx context.Context, dst netprim.Address, req SubscribeCOVRequest) error {
	if err := validateSubscribeCOVRequest(req); err != nil {
		return err
	}

	payload, err := encodeSubscribeCOVRequestPayload(req)
	if err != nil {
		return err
	}

	ackPayload, err := c.invokeConfirmedRawServiceChoice(ctx, dst, ServiceChoiceSubscribeCOV, payload)
	if err != nil {
		return err
	}
	if len(ackPayload) != 0 {
		return fmt.Errorf("%w: subscribe-cov expected simple-ack payload to be empty", ErrDecodeFailure)
	}
	return nil
}

// SubscribeCOVPropertyRequest is the typed request payload for SubscribeCOVProperty.
type SubscribeCOVPropertyRequest struct {
	SubscriberProcessIdentifier SubscriberProcessIdentifier
	MonitoredObjectIdentifier   types.ObjectIdentifier
	IssueConfirmedNotifications *bool
	Lifetime                    *COVLifetime
	MonitoredProperty           MonitoredPropertyReference
	COVIncrement                *COVIncrement
}

// NewSubscribeCOVPropertyRequest constructs a validated SubscribeCOVPropertyRequest.
func NewSubscribeCOVPropertyRequest(
	subscriberProcessIdentifier SubscriberProcessIdentifier,
	monitoredObjectIdentifier types.ObjectIdentifier,
	issueConfirmedNotifications *bool,
	lifetime *COVLifetime,
	monitoredProperty MonitoredPropertyReference,
	covIncrement *COVIncrement,
) (SubscribeCOVPropertyRequest, error) {
	req := SubscribeCOVPropertyRequest{
		SubscriberProcessIdentifier: subscriberProcessIdentifier,
		MonitoredObjectIdentifier:   monitoredObjectIdentifier,
		IssueConfirmedNotifications: issueConfirmedNotifications,
		Lifetime:                    lifetime,
		MonitoredProperty:           monitoredProperty,
		COVIncrement:                covIncrement,
	}
	if err := validateSubscribeCOVPropertyRequest(req); err != nil {
		return SubscribeCOVPropertyRequest{}, err
	}
	return req, nil
}

func validateSubscribeCOVPropertyRequest(req SubscribeCOVPropertyRequest) error {
	if !req.MonitoredObjectIdentifier.ObjectType().Valid() {
		return errors.NewValidationError("monitored object identifier", req.MonitoredObjectIdentifier, ErrEncodeFailure)
	}
	if req.COVIncrement != nil {
		if math.IsNaN(float64(*req.COVIncrement)) || math.IsInf(float64(*req.COVIncrement), 0) {
			return errors.NewValidationError("cov increment", *req.COVIncrement, ErrEncodeFailure)
		}
	}
	return nil
}

func (c *clientImpl) SubscribeCOVProperty(ctx context.Context, dst netprim.Address, req SubscribeCOVPropertyRequest) error {
	if err := validateSubscribeCOVPropertyRequest(req); err != nil {
		return err
	}

	payload, err := encodeSubscribeCOVPropertyRequestPayload(req)
	if err != nil {
		return err
	}

	ackPayload, err := c.invokeConfirmedRawServiceChoice(ctx, dst, ServiceChoiceSubscribeCOVProperty, payload)
	if err != nil {
		return err
	}
	if len(ackPayload) != 0 {
		return fmt.Errorf("%w: subscribe-cov-property expected simple-ack payload to be empty", ErrDecodeFailure)
	}
	return nil
}

func (c *clientImpl) invokeConfirmedRawServiceChoice(
	ctx context.Context,
	dst netprim.Address,
	serviceChoice ServiceChoice,
	payload []byte,
) ([]byte, error) {
	confirm, err := c.ue.InvokeConfirmed(ctx, ConfirmedRequestICI{
		Destination:           dst,
		MaxAPDULengthAccepted: c.cfg.MaxAPDULengthAccepted,
		SegmentationSupported: c.cfg.SegmentationSupported,
		MaxSegmentsAccepted:   c.cfg.MaxSegmentsAccepted,
		Priority:              c.cfg.Priority,
		ServiceRequest: ConfirmedRequest{
			ServiceChoice: serviceChoice,
			Payload:       slices.Clone(payload),
		},
	})
	if err != nil {
		return nil, classifyRemoteAPDUError(serviceChoice, err)
	}
	if confirm.ServiceResponse == nil {
		return nil, nil
	}
	return slices.Clone(confirm.ServiceResponse.Payload), nil
}

func encodeSubscribeCOVRequestPayload(req SubscribeCOVRequest) ([]byte, error) {
	out := make([]byte, 0, 24)
	out = append(out, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeUnsigned(uint32(req.SubscriberProcessIdentifier)))...)
	out = append(out, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeObjectIdentifierValue(req.MonitoredObjectIdentifier))...)
	if req.IssueConfirmedNotifications != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(2, bacencoding.EncodeBooleanValue(*req.IssueConfirmedNotifications))...)
	}
	if req.Lifetime != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(3, bacencoding.EncodeUnsigned(uint32(*req.Lifetime)))...)
	}
	return out, nil
}

func encodeSubscribeCOVPropertyRequestPayload(req SubscribeCOVPropertyRequest) ([]byte, error) {
	out := make([]byte, 0, 32)
	out = append(out, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeUnsigned(uint32(req.SubscriberProcessIdentifier)))...)
	out = append(out, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeObjectIdentifierValue(req.MonitoredObjectIdentifier))...)
	if req.IssueConfirmedNotifications != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(2, bacencoding.EncodeBooleanValue(*req.IssueConfirmedNotifications))...)
	}
	if req.Lifetime != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(3, bacencoding.EncodeUnsigned(uint32(*req.Lifetime)))...)
	}
	out = append(out, bacencoding.EncodeOpeningTag(4)...)
	out = append(out, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeUnsigned(uint32(req.MonitoredProperty.PropertyIdentifier)))...)
	if req.MonitoredProperty.ArrayIndex != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeUnsigned(*req.MonitoredProperty.ArrayIndex))...)
	}
	out = append(out, bacencoding.EncodeClosingTag(4)...)
	if req.COVIncrement != nil {
		out = append(out, bacencoding.EncodeContextPrimitive(5, bacencoding.EncodeReal(float32(*req.COVIncrement)))...)
	}
	return out, nil
}

// COVPropertyValue carries one property value entry in a COV notification.
type COVPropertyValue struct {
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	Value              []byte
	Priority           *uint8
}

// UnconfirmedCOVNotificationIndication is the typed payload of an inbound unconfirmed COV notification.
type UnconfirmedCOVNotificationIndication struct {
	Source                      netprim.Address
	SubscriberProcessIdentifier SubscriberProcessIdentifier
	InitiatingDeviceIdentifier  types.ObjectIdentifier
	MonitoredObjectIdentifier   types.ObjectIdentifier
	TimeRemaining               COVLifetime
	Values                      []COVPropertyValue
}

// UnconfirmedCOVNotificationHandler processes typed unconfirmed COV notifications.
type UnconfirmedCOVNotificationHandler func(ctx context.Context, indication UnconfirmedCOVNotificationIndication) error

// ConfirmedCOVNotificationIndication is the typed payload of an inbound
// confirmed COV notification. Its fields are identical to the unconfirmed
// form; the APDU transaction metadata remains owned by the application layer.
type ConfirmedCOVNotificationIndication = UnconfirmedCOVNotificationIndication

// ConfirmedCOVNotificationHandler processes a typed confirmed notification.
// Returning nil causes a SimpleACK; returning an error lets the ASE encode the
// protocol error selected by its confirmed-service state machine.
type ConfirmedCOVNotificationHandler func(ctx context.Context, indication ConfirmedCOVNotificationIndication) error

func (c *clientImpl) HandleConfirmedCOVNotification(handler ConfirmedCOVNotificationHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}

	return c.ue.HandleConfirmed(ServiceChoiceConfirmedCOVNotification, func(ctx context.Context, indication ConfirmedIndicationICI) (ConfirmedResponseICI, error) {
		payload, err := decodeUnconfirmedCOVNotificationPayload(indication.ServiceRequest.Payload)
		if err != nil {
			return ConfirmedResponseICI{}, err
		}
		payload.Source = indication.Source
		if err := handler(ctx, payload); err != nil {
			return ConfirmedResponseICI{}, err
		}
		return ConfirmedResponseICI{
			Destination:     indication.Source,
			InvokeID:        indication.InvokeID,
			ServiceResponse: ServiceResult{},
		}, nil
	})
}

func (c *clientImpl) HandleUnconfirmedCOVNotification(handler UnconfirmedCOVNotificationHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}

	return c.ue.HandleUnconfirmed(ServiceChoiceUnconfirmedCOVNotification, func(ctx context.Context, indication UnconfirmedIndicationICI) error {
		payload, err := decodeUnconfirmedCOVNotificationPayload(indication.ServiceRequest.Payload)
		if err != nil {
			return err
		}
		payload.Source = indication.Source
		return handler(ctx, payload)
	})
}

func decodeUnconfirmedCOVNotificationPayload(payload []byte) (UnconfirmedCOVNotificationIndication, error) {
	var out UnconfirmedCOVNotificationIndication
	cursor := 0

	_, processBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
	if err != nil {
		return out, err
	}
	processID, err := bacencoding.DecodeUnsigned(processBytes)
	if err != nil {
		return out, fmt.Errorf("%w: invalid subscriber process identifier: %v", ErrDecodeFailure, err)
	}
	out.SubscriberProcessIdentifier = SubscriberProcessIdentifier(processID)
	cursor = next

	out.InitiatingDeviceIdentifier, cursor, err = decodeExpectedContextObjectIdentifier(payload, cursor, 1)
	if err != nil {
		return out, err
	}
	if out.InitiatingDeviceIdentifier.ObjectType() != types.ObjectTypeDevice {
		return out, fmt.Errorf("%w: initiating-device-identifier must be device", ErrDecodeFailure)
	}

	out.MonitoredObjectIdentifier, cursor, err = decodeExpectedContextObjectIdentifier(payload, cursor, 2)
	if err != nil {
		return out, err
	}

	_, remainingBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 3)
	if err != nil {
		return out, err
	}
	remaining, err := bacencoding.DecodeUnsigned(remainingBytes)
	if err != nil {
		return out, fmt.Errorf("%w: invalid time-remaining: %v", ErrDecodeFailure, err)
	}
	out.TimeRemaining = COVLifetime(remaining)
	cursor = next

	cursor, out.Values, err = decodeCOVPropertyValueList(payload, cursor, 4)
	if err != nil {
		return out, err
	}
	if cursor != len(payload) {
		return out, fmt.Errorf("%w: trailing bytes in unconfirmed-cov-notification payload", ErrDecodeFailure)
	}
	return out, nil
}

// COVNotificationMultipleObject groups property values by monitored object.
type COVNotificationMultipleObject struct {
	ObjectIdentifier types.ObjectIdentifier
	Values           []COVPropertyValue
}

// UnconfirmedCOVNotificationMultipleIndication is the typed payload of an inbound unconfirmed multiple COV notification.
type UnconfirmedCOVNotificationMultipleIndication struct {
	Source                      netprim.Address
	SubscriberProcessIdentifier SubscriberProcessIdentifier
	InitiatingDeviceIdentifier  types.ObjectIdentifier
	TimeRemaining               COVLifetime
	Objects                     []COVNotificationMultipleObject
}

// UnconfirmedCOVNotificationMultipleHandler processes typed unconfirmed multiple COV notifications.
type UnconfirmedCOVNotificationMultipleHandler func(ctx context.Context, indication UnconfirmedCOVNotificationMultipleIndication) error

func (c *clientImpl) HandleUnconfirmedCOVNotificationMultiple(handler UnconfirmedCOVNotificationMultipleHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}

	return c.ue.HandleUnconfirmed(ServiceChoiceUnconfirmedCOVNotificationMultiple, func(ctx context.Context, indication UnconfirmedIndicationICI) error {
		payload, err := decodeUnconfirmedCOVNotificationMultiplePayload(indication.ServiceRequest.Payload)
		if err != nil {
			return err
		}
		payload.Source = indication.Source
		return handler(ctx, payload)
	})
}

func decodeUnconfirmedCOVNotificationMultiplePayload(payload []byte) (UnconfirmedCOVNotificationMultipleIndication, error) {
	var out UnconfirmedCOVNotificationMultipleIndication
	cursor := 0

	_, processBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
	if err != nil {
		return out, err
	}
	processID, err := bacencoding.DecodeUnsigned(processBytes)
	if err != nil {
		return out, fmt.Errorf("%w: invalid subscriber process identifier: %v", ErrDecodeFailure, err)
	}
	out.SubscriberProcessIdentifier = SubscriberProcessIdentifier(processID)
	cursor = next

	out.InitiatingDeviceIdentifier, cursor, err = decodeExpectedContextObjectIdentifier(payload, cursor, 1)
	if err != nil {
		return out, err
	}
	if out.InitiatingDeviceIdentifier.ObjectType() != types.ObjectTypeDevice {
		return out, fmt.Errorf("%w: initiating-device-identifier must be device", ErrDecodeFailure)
	}

	_, remainingBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 2)
	if err != nil {
		return out, err
	}
	remaining, err := bacencoding.DecodeUnsigned(remainingBytes)
	if err != nil {
		return out, fmt.Errorf("%w: invalid time-remaining: %v", ErrDecodeFailure, err)
	}
	out.TimeRemaining = COVLifetime(remaining)
	cursor = next

	cursor, err = expectOpeningTag(payload, cursor, 3)
	if err != nil {
		return out, err
	}
	out.Objects = make([]COVNotificationMultipleObject, 0)
	iterations := 0
	for {
		iterations++
		if iterations > len(payload)+1 {
			return out, fmt.Errorf("%w: multiple-cov object loop exceeded bounds", ErrDecodeFailure)
		}
		if isClosingTagAt(payload, cursor, 3) {
			cursor++
			break
		}

		objID, next, err := decodeExpectedContextObjectIdentifier(payload, cursor, 0)
		if err != nil {
			return out, fmt.Errorf("decode multiple-cov object identifier: %w", err)
		}
		cursor = next
		var values []COVPropertyValue
		cursor, values, err = decodeCOVPropertyValueList(payload, cursor, 1)
		if err != nil {
			return out, fmt.Errorf("decode multiple-cov property list: %w", err)
		}

		out.Objects = append(out.Objects, COVNotificationMultipleObject{ObjectIdentifier: objID, Values: values})
	}
	if cursor != len(payload) {
		return out, fmt.Errorf("%w: trailing bytes in unconfirmed-cov-notification-multiple payload", ErrDecodeFailure)
	}
	return out, nil
}

func decodeCOVPropertyValueList(payload []byte, offset int, listTag bacencoding.AppTag) (int, []COVPropertyValue, error) {
	next, err := expectOpeningTag(payload, offset, listTag)
	if err != nil {
		return offset, nil, err
	}
	cursor := next
	values := make([]COVPropertyValue, 0)
	iterations := 0
	for {
		iterations++
		if iterations > len(payload)+1 {
			return offset, nil, fmt.Errorf("%w: cov property-value list loop exceeded bounds", ErrDecodeFailure)
		}
		prevCursor := cursor
		if isClosingTagAt(payload, cursor, listTag) {
			cursor++
			return cursor, values, nil
		}
		value, next, err := decodeCOVPropertyValue(payload, cursor)
		if err != nil {
			return offset, nil, err
		}
		values = append(values, value)
		cursor = next
		if cursor <= prevCursor {
			return offset, nil, fmt.Errorf("%w: cov property-value decoder made no progress", ErrDecodeFailure)
		}
	}
}

func decodeCOVPropertyValue(payload []byte, offset int) (COVPropertyValue, int, error) {
	var out COVPropertyValue
	if offset >= len(payload) {
		return out, offset, fmt.Errorf("%w: missing property value entry", ErrDecodeFailure)
	}

	_, propBytes, next, err := decodeExpectedContextPrimitive(payload, offset, 0)
	if err != nil {
		return out, offset, err
	}
	propID, err := bacencoding.DecodeUnsigned(propBytes)
	if err != nil {
		return out, offset, fmt.Errorf("%w: invalid property identifier: %v", ErrDecodeFailure, err)
	}
	out.PropertyIdentifier = types.PropertyIdentifier(propID)
	offset = next

	if offset < len(payload) && bacencoding.LooksLikeContextPrimitiveTag(payload[offset], 1) {
		_, idxBytes, next, err := decodeExpectedContextPrimitive(payload, offset, 1)
		if err != nil {
			return out, offset, err
		}
		idx, err := bacencoding.DecodeUnsigned(idxBytes)
		if err != nil {
			return out, offset, fmt.Errorf("%w: invalid array index: %v", ErrDecodeFailure, err)
		}
		out.ArrayIndex = &idx
		offset = next
	}

	next, value, err := decodeTaggedBody(payload, offset, 2)
	if err != nil {
		return out, offset, err
	}
	out.Value = value
	offset = next

	if offset < len(payload) && bacencoding.LooksLikeContextPrimitiveTag(payload[offset], 3) {
		_, prioBytes, next, err := decodeExpectedContextPrimitive(payload, offset, 3)
		if err != nil {
			return out, offset, err
		}
		priority, err := bacencoding.DecodeUnsigned(prioBytes)
		if err != nil {
			return out, offset, fmt.Errorf("%w: invalid priority: %v", ErrDecodeFailure, err)
		}
		if priority == 0 || priority > 16 {
			return out, offset, fmt.Errorf("%w: invalid priority %d", ErrDecodeFailure, priority)
		}
		prio := uint8(priority)
		out.Priority = &prio
		offset = next
	}

	return out, offset, nil
}

func decodeExpectedContextObjectIdentifier(payload []byte, offset int, expectedTag bacencoding.AppTag) (types.ObjectIdentifier, int, error) {
	_, objBytes, next, err := decodeExpectedContextPrimitive(payload, offset, expectedTag)
	if err != nil {
		return 0, offset, err
	}
	if len(objBytes) != 4 {
		return 0, offset, fmt.Errorf("%w: invalid object identifier length %d", ErrDecodeFailure, len(objBytes))
	}
	objID := types.ObjectIdentifier(binary.BigEndian.Uint32(objBytes))
	if !objID.ObjectType().Valid() {
		return 0, offset, fmt.Errorf("%w: invalid object identifier %d", ErrDecodeFailure, objID)
	}
	return objID, next, nil
}
