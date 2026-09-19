package apdu

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/log"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

const (
	defaultClientMaxAPDULengthAccepted MaxApduLengthAccepted = 1476
)

// ClientConfig controls default ICI values used by the typed client API.
type ClientConfig struct {
	MaxAPDULengthAccepted MaxApduLengthAccepted
	SegmentationSupported SegmentationSupport
	MaxSegmentsAccepted   MaxSegmentsAccepted
	Priority              netprim.NetworkPriority
}

// DefaultClientConfig returns a ClientConfig with sensible defaults suitable
// for most BACnet/IP client applications:
//
//   - MaxAPDULengthAccepted: 1476 bytes — maximum that fits in a single Ethernet NPDU.
//   - SegmentationSupported: SegmentationSupportNo — matches DefaultASEConfig.
//   - MaxSegmentsAccepted: MaxSegmentsUnspecified — no constraint advertised to peers.
//   - Priority: NetworkPriorityNormal — standard priority for non-alarm traffic.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		MaxAPDULengthAccepted: defaultClientMaxAPDULengthAccepted,
		SegmentationSupported: SegmentationSupportNo,
		MaxSegmentsAccepted:   MaxSegmentsUnspecified,
		Priority:              netprim.NetworkPriorityNormal,
	}
}

// Client provides typed convenience methods for commonly used client services.
//
// It wraps existing ASE/B-X primitives and keeps transport/state-machine behavior
// unchanged while removing manual payload construction for the covered services.
type Client interface {
	// WhoIs sends an unconfirmed Who-Is request.
	WhoIs(ctx context.Context, dst netprim.Address, req WhoIsRequest) error

	// WhoHas sends an unconfirmed Who-Has request.
	WhoHas(ctx context.Context, dst netprim.Address, req WhoHasRequest) error

	// TimeSynchronization sends local or UTC date/time as an unconfirmed request.
	TimeSynchronization(ctx context.Context, dst netprim.Address, instant time.Time, utc bool) error

	// InvokeConfirmedRaw sends a confirmed request and returns the raw service-ack payload.
	// For SimpleACK this returns nil, nil.
	InvokeConfirmedRaw(ctx context.Context, dst netprim.Address, serviceChoice ServiceChoice, payload []byte) ([]byte, error)

	// ReadProperty sends a confirmed ReadProperty request and decodes ReadProperty-ACK.
	ReadProperty(ctx context.Context, dst netprim.Address, req ReadPropertyRequest) (ReadPropertyACK, error)

	// ReadPropertyMultiple sends a confirmed ReadPropertyMultiple request and decodes ReadPropertyMultiple-ACK.
	ReadPropertyMultiple(ctx context.Context, dst netprim.Address, req ReadPropertyMultipleRequest) (ReadPropertyMultipleACK, error)

	// WriteProperty sends a confirmed WriteProperty request and expects SimpleACK.
	WriteProperty(ctx context.Context, dst netprim.Address, req WritePropertyRequest) error

	// WritePropertyMultiple sends a confirmed WritePropertyMultiple request and expects SimpleACK.
	WritePropertyMultiple(ctx context.Context, dst netprim.Address, req WritePropertyMultipleRequest) error

	// ReadRange sends a confirmed ReadRange request and decodes ReadRange-ACK.
	ReadRange(ctx context.Context, dst netprim.Address, req ReadRangeRequest) (ReadRangeACK, error)

	// DeviceCommunicationControl sends a confirmed DeviceCommunicationControl request and expects SimpleACK.
	DeviceCommunicationControl(ctx context.Context, dst netprim.Address, req DeviceCommunicationControlRequest) error

	// ReinitializeDevice sends a confirmed ReinitializeDevice request and expects SimpleACK.
	ReinitializeDevice(ctx context.Context, dst netprim.Address, req ReinitializeDeviceRequest) error

	// SubscribeCOV sends a confirmed SubscribeCOV request and expects SimpleACK.
	SubscribeCOV(ctx context.Context, dst netprim.Address, req SubscribeCOVRequest) error

	// SubscribeCOVProperty sends a confirmed SubscribeCOVProperty request and expects SimpleACK.
	SubscribeCOVProperty(ctx context.Context, dst netprim.Address, req SubscribeCOVPropertyRequest) error

	// RegisterIAmHandler registers a typed handler for incoming unconfirmed I-Am indications.
	RegisterIAmHandler(handler IAmHandler) error

	// Discover sends Who-Is and collects I-Am indications within a window.
	Discover(ctx context.Context, req DiscoverRequest) ([]IAmIndication, error)

	// HandleIHave registers a typed handler for incoming unconfirmed I-Have indications.
	HandleIHave(handler IHaveHandler) error

	// HandleUnconfirmedCOVNotification registers a typed handler for inbound unconfirmed COV notifications.
	HandleUnconfirmedCOVNotification(handler UnconfirmedCOVNotificationHandler) error

	// HandleUnconfirmedCOVNotificationMultiple registers a typed handler for inbound unconfirmed multiple COV notifications.
	HandleUnconfirmedCOVNotificationMultiple(handler UnconfirmedCOVNotificationMultipleHandler) error
}

func (c *clientImpl) TimeSynchronization(ctx context.Context, dst netprim.Address, instant time.Time, utc bool) error {
	payload, err := bacencoding.EncodeDateTimeValue(bacencoding.BACnetDateTime{
		Date: bacencoding.BACnetDate{
			Year: uint16(instant.Year()), Month: uint8(instant.Month()), Day: uint8(instant.Day()),
			Weekday: uint8(instant.Weekday()+6)%7 + 1,
		},
		Time: bacencoding.BACnetTime{
			Hour: uint8(instant.Hour()), Minute: uint8(instant.Minute()), Second: uint8(instant.Second()),
			Hundredths: uint8(instant.Nanosecond() / 10_000_000),
		},
	})
	if err != nil {
		return fmt.Errorf("encode time-synchronization: %w", err)
	}
	choice := ServiceChoiceTimeSynchronization
	if utc {
		choice = ServiceChoiceUTCTimeSynchronization
	}
	return c.ue.SendUnconfirmed(ctx, UnconfirmedRequestICI{
		Destination:    dst,
		Priority:       c.cfg.Priority,
		ServiceRequest: UnconfirmedRequest{ServiceChoice: choice, Payload: payload},
	})
}

// ConfirmedCodec describes a typed confirmed service codec.
type ConfirmedCodec[Req any, Ack any] struct {
	ServiceChoice ServiceChoice
	EncodeRequest func(req Req) ([]byte, error)
	DecodeACK     func(payload []byte) (Ack, error)
}

// InvokeConfirmedTyped invokes a confirmed service via codec and decodes its ACK.
func InvokeConfirmedTyped[Req any, Ack any](
	ctx context.Context,
	client Client,
	dst netprim.Address,
	codec ConfirmedCodec[Req, Ack],
	req Req,
) (Ack, error) {
	var zero Ack

	if codec.EncodeRequest == nil || codec.DecodeACK == nil {
		return zero, errors.NewValidationError("codec", codec.ServiceChoice, ErrInvalidASEConfig)
	}

	payload, err := codec.EncodeRequest(req)
	if err != nil {
		log.Logger.Error("apdu invoke typed encode request", "error", err, "service", codec.ServiceChoice)
		return zero, err
	}

	ackPayload, err := client.InvokeConfirmedRaw(ctx, dst, codec.ServiceChoice, payload)
	if err != nil {
		log.Logger.Error("apdu invoke typed confirmed raw", "error", err, "service", codec.ServiceChoice)
		return zero, err
	}

	return codec.DecodeACK(ackPayload)
}

type clientImpl struct {
	ue  UserElement
	cfg ClientConfig
	iam *iAmDispatcher
}

// NewClient constructs a typed client wrapper around the given ASE.
func NewClient(ase ASE, cfg ClientConfig) (Client, error) {
	ue, err := NewUserElement(ase)
	if err != nil {
		log.Logger.Error("apdu new client create user element", "error", err)
		return nil, err
	}

	if cfg.MaxAPDULengthAccepted == 0 {
		cfg.MaxAPDULengthAccepted = defaultClientMaxAPDULengthAccepted
	}

	if cfg.MaxSegmentsAccepted == 0 {
		cfg.MaxSegmentsAccepted = MaxSegmentsUnspecified
	}

	if !cfg.Priority.Valid() {
		cfg.Priority = netprim.NetworkPriorityNormal
	}

	if !cfg.MaxSegmentsAccepted.Valid() {
		return nil, errors.NewValidationError("max segments accepted", cfg.MaxSegmentsAccepted, ErrInvalidASEConfig)
	}

	return &clientImpl{ue: ue, cfg: cfg, iam: newIAmDispatcher(ue)}, nil
}

// WhoIsRequest models the optional device-instance range fields of Who-Is.
type WhoIsRequest struct {
	// LowLimit is the optional lower bound of the device instance range.
	LowLimit *types.DeviceInstance
	// HighLimit is the optional upper bound of the device instance range.
	HighLimit *types.DeviceInstance
}

func NewWhoIsRequest() WhoIsRequest {
	return WhoIsRequest{LowLimit: nil, HighLimit: nil}
}

// NewWhoIsRequestWithLimits constructs a validated WhoIsRequest.
// lowLimit and highLimit must either both be nil or both be set.
func NewWhoIsRequestWithLimits(lowLimit, highLimit types.DeviceInstance) (WhoIsRequest, error) {
	res := WhoIsRequest{LowLimit: &lowLimit, HighLimit: &highLimit}
	if err := validateWhoIsRequest(res); err != nil {
		return WhoIsRequest{}, err
	}
	return res, nil
}

func validateWhoIsRequest(req WhoIsRequest) error {
	if (req.LowLimit == nil) != (req.HighLimit == nil) {
		return errors.NewValidationError("who-is limits", req, ErrEncodeFailure)
	}

	if req.LowLimit == nil {
		return nil
	}

	if !req.LowLimit.Valid() {
		return errors.NewValidationError("low limit", *req.LowLimit, ErrEncodeFailure)
	}

	if !req.HighLimit.Valid() {
		return errors.NewValidationError("high limit", *req.HighLimit, ErrEncodeFailure)
	}

	if *req.LowLimit > *req.HighLimit {
		return errors.NewValidationError("who-is limits", req, ErrEncodeFailure)
	}

	return nil
}

func (c *clientImpl) WhoIs(ctx context.Context, dst netprim.Address, req WhoIsRequest) error {
	if err := validateWhoIsRequest(req); err != nil {
		log.Logger.Error("apdu who-is validate request", "error", err)
		return err
	}

	payload, err := encodeWhoIsPayload(req)
	if err != nil {
		log.Logger.Error("apdu who-is encode payload", "error", err)
		return err
	}

	return c.ue.SendUnconfirmed(ctx, UnconfirmedRequestICI{
		Destination: dst,
		Priority:    c.cfg.Priority,
		ServiceRequest: UnconfirmedRequest{
			ServiceChoice: ServiceChoiceWhoIs,
			Payload:       payload,
		},
	})
}

func (c *clientImpl) InvokeConfirmedRaw(
	ctx context.Context,
	dst netprim.Address,
	serviceChoice ServiceChoice,
	payload []byte,
) ([]byte, error) {
	if !IsConfirmedServiceChoice(serviceChoice) {
		return nil, errors.NewValidationError("service choice", serviceChoice, ErrInvalidServiceChoice)
	}

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
		log.Logger.Error("apdu invoke confirmed raw", "error", err)
		return nil, classifyRemoteAPDUError(serviceChoice, err)
	}

	if confirm.ServiceResponse == nil {
		return nil, nil
	}

	return slices.Clone(confirm.ServiceResponse.Payload), nil
}

// WhoHasRequest models an unconfirmed Who-Has request.
//
// LowLimit and HighLimit must be both set or both nil.
// Exactly one of ObjectIdentifier or ObjectName must be set.
type WhoHasRequest struct {
	LowLimit         *types.DeviceInstance
	HighLimit        *types.DeviceInstance
	ObjectIdentifier *types.ObjectIdentifier
	ObjectName       *string
}

// NewWhoHasByObjectIdentifier constructs a validated WhoHasRequest that
// searches by object identifier.
func NewWhoHasByObjectIdentifier(
	lowLimit, highLimit *types.DeviceInstance,
	objectIdentifier types.ObjectIdentifier,
) (WhoHasRequest, error) {
	req := WhoHasRequest{
		LowLimit:         lowLimit,
		HighLimit:        highLimit,
		ObjectIdentifier: &objectIdentifier,
	}

	if err := validateWhoHasRequest(req); err != nil {
		return WhoHasRequest{}, err
	}

	return req, nil
}

// NewWhoHasByObjectName constructs a validated WhoHasRequest that searches by
// object name.
func NewWhoHasByObjectName(
	lowLimit, highLimit *types.DeviceInstance,
	objectName string,
) (WhoHasRequest, error) {
	req := WhoHasRequest{
		LowLimit:  lowLimit,
		HighLimit: highLimit,
		ObjectName: func() *string {
			v := objectName
			return ptr(v)
		}(),
	}

	if err := validateWhoHasRequest(req); err != nil {
		return WhoHasRequest{}, err
	}

	return req, nil
}

func validateWhoHasRequest(req WhoHasRequest) error {
	if (req.LowLimit == nil) != (req.HighLimit == nil) {
		return errors.NewValidationError("who-has limits", req, ErrEncodeFailure)
	}

	if req.LowLimit != nil {
		if !req.LowLimit.Valid() {
			return errors.NewValidationError("low limit", *req.LowLimit, ErrEncodeFailure)
		}

		if !req.HighLimit.Valid() {
			return errors.NewValidationError("high limit", *req.HighLimit, ErrEncodeFailure)
		}

		if *req.LowLimit > *req.HighLimit {
			return errors.NewValidationError("who-has limits", req, ErrEncodeFailure)
		}
	}

	hasObjectID := req.ObjectIdentifier != nil
	hasObjectName := req.ObjectName != nil
	if hasObjectID == hasObjectName {
		return errors.NewValidationError("object specifier", req, ErrEncodeFailure)
	}

	if hasObjectID && !req.ObjectIdentifier.ObjectType().Valid() {
		return errors.NewValidationError("object identifier", *req.ObjectIdentifier, ErrEncodeFailure)
	}

	if hasObjectName {
		if len(*req.ObjectName) == 0 {
			return errors.NewValidationError("object name", *req.ObjectName, ErrEncodeFailure)
		}

		if !bacencoding.IsASCIIString(*req.ObjectName) {
			return errors.NewValidationError("object name", *req.ObjectName, ErrEncodeFailure)
		}
	}

	return nil
}

func (c *clientImpl) WhoHas(ctx context.Context, dst netprim.Address, req WhoHasRequest) error {
	if err := validateWhoHasRequest(req); err != nil {
		log.Logger.Error("apdu who-has validate request", "error", err)
		return err
	}

	payload, err := encodeWhoHasPayload(req)
	if err != nil {
		log.Logger.Error("apdu who-has encode payload", "error", err)
		return err
	}

	return c.ue.SendUnconfirmed(ctx, UnconfirmedRequestICI{
		Destination: dst,
		Priority:    c.cfg.Priority,
		ServiceRequest: UnconfirmedRequest{
			ServiceChoice: ServiceChoiceWhoHas,
			Payload:       payload,
		},
	})
}

func encodeWhoHasPayload(req WhoHasRequest) ([]byte, error) {
	out := make([]byte, 0, 32)

	if req.LowLimit != nil {
		out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(*req.LowLimit)))...)
		out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(*req.HighLimit)))...)
	}

	if req.ObjectIdentifier != nil {
		objRaw := uint32(*req.ObjectIdentifier)
		out = append(out, encodeContextPrimitive(2, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
		return out, nil
	}

	// Character-string value for ANSI X3.4/UTF-8 basic ASCII subset: first byte charset=0.
	charValue, err := bacencoding.EncodeCharacterStringValue(*req.ObjectName)
	if err != nil {
		return nil, fmt.Errorf("%w: object name character-string: %v", ErrEncodeFailure, err)
	}
	out = append(out, encodeContextPrimitive(3, charValue)...)
	return out, nil
}

func encodeWhoIsPayload(req WhoIsRequest) ([]byte, error) {
	if req.LowLimit == nil {
		return nil, nil
	}

	// Per ASHRAE 135 clause 16.10.1, the device-instance range limits are
	// context-tagged: deviceInstanceRangeLowLimit is context tag 0 and
	// deviceInstanceRangeHighLimit is context tag 1 (each an unsigned value).
	lowBytes := encodeContextPrimitive(0, encodeUnsigned(uint32(*req.LowLimit)))
	highBytes := encodeContextPrimitive(1, encodeUnsigned(uint32(*req.HighLimit)))

	out := make([]byte, 0, len(lowBytes)+len(highBytes))
	out = append(out, lowBytes...)
	out = append(out, highBytes...)
	return out, nil
}

// ReadPropertyRequest models the confirmed ReadProperty service parameters.
type ReadPropertyRequest struct {
	ObjectIdentifier   types.ObjectIdentifier
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
}

// NewReadPropertyRequest constructs a validated ReadPropertyRequest.
func NewReadPropertyRequest(objectIdentifier types.ObjectIdentifier, propertyIdentifier types.PropertyIdentifier, arrayIndex *uint32) (ReadPropertyRequest, error) {
	res := ReadPropertyRequest{
		ObjectIdentifier:   objectIdentifier,
		PropertyIdentifier: propertyIdentifier,
		ArrayIndex:         arrayIndex,
	}
	if err := validateReadPropertyRequest(res); err != nil {
		return ReadPropertyRequest{}, err
	}
	return res, nil
}

func validateReadPropertyRequest(req ReadPropertyRequest) error {
	if !req.ObjectIdentifier.ObjectType().Valid() {
		return errors.NewValidationError("object identifier", req.ObjectIdentifier, ErrEncodeFailure)
	}
	return nil
}

// ReadPropertyACK models the decoded ReadProperty-ACK payload.
type ReadPropertyACK struct {
	ObjectIdentifier   types.ObjectIdentifier
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	PropertyValue      []byte
}

func (c *clientImpl) ReadProperty(ctx context.Context, dst netprim.Address, req ReadPropertyRequest) (ReadPropertyACK, error) {
	if err := validateReadPropertyRequest(req); err != nil {
		return ReadPropertyACK{}, err
	}

	codec := ConfirmedCodec[ReadPropertyRequest, ReadPropertyACK]{
		ServiceChoice: ServiceChoiceReadProperty,
		EncodeRequest: encodeReadPropertyRequestPayload,
		DecodeACK:     decodeReadPropertyACKPayload,
	}

	return InvokeConfirmedTyped(ctx, c, dst, codec, req)
}

// IAmIndication is the typed payload of an inbound unconfirmed I-Am service.
type IAmIndication struct {
	Source                netprim.Address
	DeviceIdentifier      types.ObjectIdentifier
	MaxAPDULengthAccepted MaxApduLengthAccepted
	SegmentationSupported SegmentationSupport
	VendorID              uint16
}

// IAmHandler processes typed I-Am indications.
type IAmHandler func(ctx context.Context, indication IAmIndication) error

func (c *clientImpl) RegisterIAmHandler(handler IAmHandler) error {
	if c.iam == nil {
		return errors.NewValidationError("i-am dispatcher", nil, ErrInvalidASEConfig)
	}

	return c.iam.RegisterHandler(handler)
}

// IHaveIndication is the typed payload of an inbound unconfirmed I-Have service.
type IHaveIndication struct {
	Source           netprim.Address
	DeviceIdentifier types.ObjectIdentifier
	ObjectIdentifier types.ObjectIdentifier
	ObjectName       string
}

// IHaveHandler processes typed I-Have indications.
type IHaveHandler func(ctx context.Context, indication IHaveIndication) error

func (c *clientImpl) HandleIHave(handler IHaveHandler) error {
	if handler == nil {
		return errors.NewValidationError("handler", nil, ErrHandlerNotFound)
	}

	return c.ue.HandleUnconfirmed(ServiceChoiceIHave, func(ctx context.Context, indication UnconfirmedIndicationICI) error {
		payload, err := decodeIHavePayload(indication.ServiceRequest.Payload)
		if err != nil {
			return err
		}

		return handler(ctx, IHaveIndication{
			Source:           indication.Source,
			DeviceIdentifier: payload.DeviceIdentifier,
			ObjectIdentifier: payload.ObjectIdentifier,
			ObjectName:       payload.ObjectName,
		})
	})
}

func decodeIHavePayload(payload []byte) (IHaveIndication, error) {
	var out IHaveIndication

	_, devObjBytes, next, err := decodeExpectedApplicationPrimitive(payload, 0, 12)
	if err != nil {
		return IHaveIndication{}, err
	}
	if len(devObjBytes) != 4 {
		return IHaveIndication{}, fmt.Errorf("%w: invalid i-have device-identifier length %d", ErrDecodeFailure, len(devObjBytes))
	}
	out.DeviceIdentifier = types.ObjectIdentifier(binary.BigEndian.Uint32(devObjBytes))
	if out.DeviceIdentifier.ObjectType() != types.ObjectTypeDevice {
		return IHaveIndication{}, fmt.Errorf("%w: i-have device-identifier must be device", ErrDecodeFailure)
	}

	_, objBytes, next, err := decodeExpectedApplicationPrimitive(payload, next, 12)
	if err != nil {
		return IHaveIndication{}, err
	}
	if len(objBytes) != 4 {
		return IHaveIndication{}, fmt.Errorf("%w: invalid i-have object-identifier length %d", ErrDecodeFailure, len(objBytes))
	}
	out.ObjectIdentifier = types.ObjectIdentifier(binary.BigEndian.Uint32(objBytes))
	if !out.ObjectIdentifier.ObjectType().Valid() {
		return IHaveIndication{}, fmt.Errorf("%w: invalid i-have object-identifier", ErrDecodeFailure)
	}

	_, nameBytes, end, err := decodeExpectedApplicationPrimitive(payload, next, 7)
	if err != nil {
		return IHaveIndication{}, err
	}
	name, err := bacencoding.DecodeCharacterStringValue(nameBytes)
	if err != nil {
		return IHaveIndication{}, fmt.Errorf("%w: invalid i-have object-name: %v", ErrDecodeFailure, err)
	}
	out.ObjectName = name

	if end != len(payload) {
		return IHaveIndication{}, fmt.Errorf("%w: trailing bytes in i-have payload", ErrDecodeFailure)
	}

	return out, nil
}

func decodeIAmPayload(payload []byte) (IAmIndication, error) {
	var out IAmIndication

	_, objBytes, next, err := decodeExpectedApplicationPrimitive(payload, 0, 12)
	if err != nil {
		return IAmIndication{}, err
	}
	if len(objBytes) != 4 {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am object-identifier length %d", ErrDecodeFailure, len(objBytes))
	}
	out.DeviceIdentifier = types.ObjectIdentifier(binary.BigEndian.Uint32(objBytes))
	if out.DeviceIdentifier.ObjectType() != types.ObjectTypeDevice {
		return IAmIndication{}, fmt.Errorf("%w: i-am object-identifier must be device", ErrDecodeFailure)
	}

	_, maxAPDUBytes, next, err := decodeExpectedApplicationPrimitive(payload, next, 2)
	if err != nil {
		return IAmIndication{}, err
	}
	maxAPDU, err := decodeUnsigned(maxAPDUBytes)
	if err != nil {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am max-apdu: %v", ErrDecodeFailure, err)
	}
	if maxAPDU > 0xFFFF {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am max-apdu value %d", ErrDecodeFailure, maxAPDU)
	}
	out.MaxAPDULengthAccepted = MaxApduLengthAccepted(maxAPDU)

	_, segmentationBytes, next, err := decodeExpectedApplicationPrimitive(payload, next, 9)
	if err != nil {
		return IAmIndication{}, err
	}
	segmentationRaw, err := decodeUnsigned(segmentationBytes)
	if err != nil {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am segmentation-supported: %v", ErrDecodeFailure, err)
	}
	if segmentationRaw > uint32(SegmentationSupportBoth) {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am segmentation-supported %d", ErrDecodeFailure, segmentationRaw)
	}
	out.SegmentationSupported = SegmentationSupport(segmentationRaw)

	_, vendorBytes, end, err := decodeExpectedApplicationPrimitive(payload, next, 2)
	if err != nil {
		return IAmIndication{}, err
	}
	vendorID, err := decodeUnsigned(vendorBytes)
	if err != nil {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am vendor-id: %v", ErrDecodeFailure, err)
	}
	if vendorID > 0xFFFF {
		return IAmIndication{}, fmt.Errorf("%w: invalid i-am vendor-id %d", ErrDecodeFailure, vendorID)
	}
	out.VendorID = uint16(vendorID)

	if end != len(payload) {
		return IAmIndication{}, fmt.Errorf("%w: trailing bytes in i-am payload", ErrDecodeFailure)
	}

	return out, nil
}

func encodeReadPropertyRequestPayload(req ReadPropertyRequest) ([]byte, error) {
	objRaw := uint32(req.ObjectIdentifier)
	out := make([]byte, 0, 14)

	out = append(out, encodeContextPrimitive(0, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
	out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.PropertyIdentifier)))...)

	if req.ArrayIndex != nil {
		out = append(out, encodeContextPrimitive(2, encodeUnsigned(*req.ArrayIndex))...)
	}

	return out, nil
}

func decodeReadPropertyACKPayload(payload []byte) (ReadPropertyACK, error) {
	cursor := 0

	objTag, objValue, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
	if err != nil {
		return ReadPropertyACK{}, err
	}
	if len(objValue) != 4 {
		return ReadPropertyACK{}, fmt.Errorf("%w: invalid object-identifier length %d", ErrDecodeFailure, len(objValue))
	}
	objID := types.ObjectIdentifier(binary.BigEndian.Uint32(objValue))
	if !objID.ObjectType().Valid() {
		return ReadPropertyACK{}, fmt.Errorf("%w: invalid object-identifier %d", ErrDecodeFailure, objID)
	}
	cursor = next
	_ = objTag

	_, propValue, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
	if err != nil {
		return ReadPropertyACK{}, err
	}
	propID, err := decodeUnsigned(propValue)
	if err != nil {
		return ReadPropertyACK{}, fmt.Errorf("%w: invalid property-identifier: %v", ErrDecodeFailure, err)
	}
	cursor = next

	res := ReadPropertyACK{
		ObjectIdentifier:   objID,
		PropertyIdentifier: types.PropertyIdentifier(propID),
	}

	if cursor >= len(payload) {
		return ReadPropertyACK{}, fmt.Errorf("%w: missing property-value opening tag", ErrDecodeFailure)
	}

	if looksLikeContextPrimitiveTag(payload[cursor], 2) {
		_, arrValue, next, err := decodeExpectedContextPrimitive(payload, cursor, 2)
		if err != nil {
			return ReadPropertyACK{}, err
		}
		arrIdx, err := decodeUnsigned(arrValue)
		if err != nil {
			return ReadPropertyACK{}, fmt.Errorf("%w: invalid array-index: %v", ErrDecodeFailure, err)
		}
		res.ArrayIndex = &arrIdx
		cursor = next
	}

	if cursor >= len(payload) {
		return ReadPropertyACK{}, fmt.Errorf("%w: missing property-value opening tag", ErrDecodeFailure)
	}

	tag, hdrLen, valueLen, err := bacencoding.ParseTag(payload[cursor:])
	if err != nil {
		return ReadPropertyACK{}, fmt.Errorf("%w: decode property-value opening tag: %v", ErrDecodeFailure, err)
	}
	if !tag.ContextSpecific || tag.TagNumber != 3 || !tag.Opening {
		return ReadPropertyACK{}, fmt.Errorf("%w: expected opening-tag(3)", ErrDecodeFailure)
	}
	if valueLen != 0 {
		return ReadPropertyACK{}, fmt.Errorf("%w: invalid opening-tag(3)", ErrDecodeFailure)
	}
	cursor += hdrLen

	valueStart := cursor
	stack := []bacencoding.AppTag{3}

	for cursor < len(payload) {
		t, hLen, vLen, parseErr := bacencoding.ParseTag(payload[cursor:])
		if parseErr != nil {
			return ReadPropertyACK{}, fmt.Errorf("%w: decode property-value: %v", ErrDecodeFailure, parseErr)
		}

		switch {
		case t.Opening:
			stack = append(stack, t.TagNumber)
			cursor += hLen
		case t.Closing:
			if len(stack) == 0 {
				return ReadPropertyACK{}, fmt.Errorf("%w: unbalanced closing tag", ErrDecodeFailure)
			}
			expected := stack[len(stack)-1]
			if expected != t.TagNumber {
				return ReadPropertyACK{}, fmt.Errorf("%w: mismatched closing tag, expected %d got %d", ErrDecodeFailure, expected, t.TagNumber)
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				res.PropertyValue = slices.Clone(payload[valueStart:cursor])
				if cursor+hLen != len(payload) {
					return ReadPropertyACK{}, fmt.Errorf("%w: trailing bytes after read-property-ack payload", ErrDecodeFailure)
				}
				return res, nil
			}
			cursor += hLen
		default:
			cursor += hLen + vLen
		}
	}

	return ReadPropertyACK{}, fmt.Errorf("%w: missing closing-tag(3)", ErrDecodeFailure)
}

func decodeExpectedContextPrimitive(payload []byte, offset int, expectedTag bacencoding.AppTag) (tagInfo, []byte, int, error) {
	tag, value, next, err := bacencoding.DecodeExpectedContextPrimitive(payload, offset, expectedTag)
	if err != nil {
		return tagInfo{}, nil, offset, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}
	return tagInfo{tagNumber: tag.TagNumber, contextSpecific: tag.ContextSpecific, opening: tag.Opening, closing: tag.Closing}, value, next, nil
}

func decodeExpectedApplicationPrimitive(payload []byte, offset int, expectedTag bacencoding.AppTag) (tagInfo, []byte, int, error) {
	tag, value, next, err := bacencoding.DecodeExpectedApplicationPrimitive(payload, offset, expectedTag)
	if err != nil {
		return tagInfo{}, nil, offset, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}
	return tagInfo{tagNumber: tag.TagNumber, contextSpecific: tag.ContextSpecific, opening: tag.Opening, closing: tag.Closing}, value, next, nil
}

func looksLikeContextPrimitiveTag(b byte, tagNumber bacencoding.AppTag) bool {
	return bacencoding.LooksLikeContextPrimitiveTag(b, tagNumber)
}

func encodeContextPrimitive(tagNumber uint8, value []byte) []byte {
	return bacencoding.EncodeContextPrimitive(tagNumber, value)
}

func encodeUnsigned(v uint32) []byte {
	return bacencoding.EncodeUnsigned(v)
}

func decodeUnsigned(raw []byte) (uint32, error) {
	v, err := bacencoding.DecodeUnsigned(raw)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	return v, nil
}

type tagInfo struct {
	tagNumber       bacencoding.AppTag
	contextSpecific bool
	opening         bool
	closing         bool
}
