package apdu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	bacneterrors "github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

// RemoteErrorAPDU indicates the peer completed a confirmed request with an Error APDU.
// ErrorClass and ErrorCode are decoded from the wire payload. If the payload was
// malformed and could not be decoded, ParseFailed is true and ErrorClass /
// ErrorCode are set to ErrorClassUnknown / ErrorCodeUnknown.
type RemoteErrorAPDU struct {
	InvokeId      InvokeID
	ServiceChoice ServiceChoice
	ErrorClass    ErrorClass
	ErrorCode     ErrorCode
	ParseFailed   bool
}

func (e RemoteErrorAPDU) Error() string {
	if e.ParseFailed {
		return fmt.Sprintf("remote error APDU for service %s: (malformed payload)", e.ServiceChoice)
	}
	return fmt.Sprintf("remote error APDU for service %s: %s/%s", e.ServiceChoice, e.ErrorClass, e.ErrorCode)
}

func (e RemoteErrorAPDU) Unwrap() error {
	return ErrRemoteError
}

// decodeErrorPayload parses the two consecutive application-tagged ENUMERATED
// values (error-class, error-code) from a BACnet Error-PDU body (clause 18.1).
//
// The BACnet-Error SEQUENCE on the wire is:
//
//	[app-tag-9 error-class] [app-tag-9 error-code]
//
// Trailing bytes beyond the two fields are tolerated for forward-compatibility
// with future revisions of the standard. Returns ErrDecodeFailure if either
// field cannot be parsed.
func decodeErrorPayload(payload []byte) (ErrorClass, ErrorCode, error) {
	const enumeratedTag = 9 // BACnet application tag for ENUMERATED (clause 20.2.11)

	_, classRaw, next, err := decodeExpectedApplicationPrimitive(payload, 0, enumeratedTag)
	if err != nil {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: error-class: %v", ErrDecodeFailure, err)
	}

	classVal, err := decodeUnsigned(classRaw)
	if err != nil {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: error-class value: %v", ErrDecodeFailure, err)
	}

	_, codeRaw, _, err := decodeExpectedApplicationPrimitive(payload, next, enumeratedTag)
	if err != nil {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: error-code: %v", ErrDecodeFailure, err)
	}

	codeVal, err := decodeUnsigned(codeRaw)
	if err != nil {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: error-code value: %v", ErrDecodeFailure, err)
	}

	class := ErrorClass(classVal)
	code := ErrorCode(codeVal)

	if !code.Valid() {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: invalid error-code value: %v", ErrDecodeFailure, code)
	}

	if !class.Valid() {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: invalid error-class value: %v", ErrDecodeFailure, class)
	}

	if codeVal != 0 && (code.Class() != class) { //code val should match class, other is allowed always
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: error-class missmatch: got %v, error code indicates %v", ErrDecodeFailure, class, code.Class())
	}

	return ErrorClass(classVal), ErrorCode(codeVal), nil
}

// RemoteRejectAPDU indicates the peer completed a confirmed request with a Reject APDU.
type RemoteRejectAPDU struct {
	InvokeId      InvokeID
	ServiceChoice ServiceChoice
	RejectReason  RejectReason
}

func (e RemoteRejectAPDU) Error() string {
	return fmt.Sprintf("remote reject APDU for service %s: %s", e.ServiceChoice, e.RejectReason)
}

func (e RemoteRejectAPDU) Unwrap() error {
	return ErrRemoteReject
}

// RemoteAbortAPDU indicates the peer completed a confirmed request with an Abort APDU.
type RemoteAbortAPDU struct {
	InvokeId      InvokeID
	ServiceChoice ServiceChoice
	AbortReason   AbortReason
}

func (e RemoteAbortAPDU) Error() string {
	return fmt.Sprintf("remote abort APDU for service %s: %s", e.ServiceChoice, e.AbortReason)
}

func (e RemoteAbortAPDU) Unwrap() error {
	return ErrRemoteAbort
}

func classifyRemoteAPDUError(serviceChoice ServiceChoice, err error) error {
	if err == nil {
		return nil
	}

	if tErr, ok := asType[*TransactionError](err); ok {
		switch {
		case errors.Is(tErr.Err, ErrRemoteError):
			e := RemoteErrorAPDU{
				InvokeId:      tErr.InboundApdu.InvokeID,
				ServiceChoice: tErr.InboundApdu.ServiceChoice,
				ErrorClass:    ErrorClassUnknown,
				ErrorCode:     ErrorCodeUnknown,
			}
			if ec, code, err := decodeErrorPayload(tErr.InboundApdu.Payload); err == nil {
				e.ErrorClass = ec
				e.ErrorCode = code
			} else {
				e.ParseFailed = true
			}
			return e
		case errors.Is(tErr.Err, ErrRemoteReject):
			var reason RejectReason
			if tErr.InboundApdu != nil && len(tErr.InboundApdu.Payload) > 0 {
				reason = RejectReason(tErr.InboundApdu.Payload[0])
			}
			return RemoteRejectAPDU{
				InvokeId:      tErr.InboundApdu.InvokeID,
				ServiceChoice: serviceChoice,
				RejectReason:  reason,
			}
		case errors.Is(tErr.Err, ErrRemoteAbort):
			var reason AbortReason
			if tErr.InboundApdu != nil && len(tErr.InboundApdu.Payload) > 0 {
				reason = AbortReason(tErr.InboundApdu.Payload[0])
			}
			return RemoteAbortAPDU{
				InvokeId:      tErr.InboundApdu.InvokeID,
				ServiceChoice: serviceChoice,
				AbortReason:   reason,
			}
		}
	}

	return err
}

// PropertyReference identifies one property (and optional array index) on an object.
type PropertyReference struct {
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
}

// ReadAccessSpecification defines one object and its requested properties for ReadPropertyMultiple.
type ReadAccessSpecification struct {
	ObjectIdentifier types.ObjectIdentifier
	Properties       []PropertyReference
}

// ReadPropertyMultipleRequest is the typed request payload for ReadPropertyMultiple.
type ReadPropertyMultipleRequest struct {
	Specs []ReadAccessSpecification
}

// NewReadPropertyMultipleRequest constructs a validated ReadPropertyMultipleRequest.
func NewReadPropertyMultipleRequest(specs []ReadAccessSpecification) (ReadPropertyMultipleRequest, error) {
	specsCopy := make([]ReadAccessSpecification, len(specs))
	copy(specsCopy, specs)
	req := ReadPropertyMultipleRequest{Specs: specsCopy}
	if err := validateReadPropertyMultipleRequest(req); err != nil {
		return ReadPropertyMultipleRequest{}, err
	}
	return req, nil
}

func validateReadPropertyMultipleRequest(req ReadPropertyMultipleRequest) error {
	if len(req.Specs) == 0 {
		return bacneterrors.NewValidationError("specs", len(req.Specs), ErrEncodeFailure)
	}

	for i, spec := range req.Specs {
		if !spec.ObjectIdentifier.ObjectType().Valid() {
			return bacneterrors.NewValidationError(fmt.Sprintf("specs[%d].object identifier", i), spec.ObjectIdentifier, ErrEncodeFailure)
		}
		if len(spec.Properties) == 0 {
			return bacneterrors.NewValidationError(fmt.Sprintf("specs[%d].properties", i), len(spec.Properties), ErrEncodeFailure)
		}
	}

	return nil
}

// ReadPropertyResult carries one property result entry from ReadPropertyMultiple-ACK.
type ReadPropertyResult struct {
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	PropertyValue      []byte
	Error              []byte
}

// DecodeError decodes the per-property error of a ReadPropertyMultiple result
// into its error-class and error-code. It is meaningful only when this result
// carried an error rather than a value (Error != nil); it returns
// ErrDecodeFailure when Error is empty or malformed.
func (r ReadPropertyResult) DecodeError() (ErrorClass, ErrorCode, error) {
	if len(r.Error) == 0 {
		return ErrorClassUnknown, ErrorCodeUnknown, fmt.Errorf("%w: read-property result has no error", ErrDecodeFailure)
	}
	return decodeErrorPayload(r.Error)
}

// ReadAccessResult carries all property results for one object.
type ReadAccessResult struct {
	ObjectIdentifier types.ObjectIdentifier
	Results          []ReadPropertyResult
}

// ReadPropertyMultipleACK is the typed ACK payload for ReadPropertyMultiple.
type ReadPropertyMultipleACK struct {
	Results []ReadAccessResult
}

func (c *clientImpl) ReadPropertyMultiple(ctx context.Context, dst netprim.Address, req ReadPropertyMultipleRequest) (ReadPropertyMultipleACK, error) {
	if err := validateReadPropertyMultipleRequest(req); err != nil {
		return ReadPropertyMultipleACK{}, err
	}

	codec := ConfirmedCodec[ReadPropertyMultipleRequest, ReadPropertyMultipleACK]{
		ServiceChoice: ServiceChoiceReadPropertyMultiple,
		EncodeRequest: encodeReadPropertyMultipleRequestPayload,
		DecodeACK:     decodeReadPropertyMultipleACKPayload,
	}

	ack, err := InvokeConfirmedTyped(ctx, c, dst, codec, req)
	if err != nil {
		return ReadPropertyMultipleACK{}, classifyRemoteAPDUError(ServiceChoiceReadPropertyMultiple, err)
	}

	return ack, nil
}

func encodeReadPropertyMultipleRequestPayload(req ReadPropertyMultipleRequest) ([]byte, error) {
	out := make([]byte, 0, 64)

	for _, spec := range req.Specs {
		objRaw := uint32(spec.ObjectIdentifier)
		out = append(out, encodeContextPrimitive(0, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
		out = append(out, encodeOpeningTag(1)...)
		for _, prop := range spec.Properties {
			out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(prop.PropertyIdentifier)))...)
			if prop.ArrayIndex != nil {
				out = append(out, encodeContextPrimitive(1, encodeUnsigned(*prop.ArrayIndex))...)
			}
		}
		out = append(out, encodeClosingTag(1)...)
	}

	return out, nil
}

func decodeReadPropertyMultipleACKPayload(payload []byte) (ReadPropertyMultipleACK, error) {
	cursor := 0
	ack := ReadPropertyMultipleACK{Results: make([]ReadAccessResult, 0)}

	for cursor < len(payload) {
		_, objBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
		if err != nil {
			return ReadPropertyMultipleACK{}, err
		}
		if len(objBytes) != 4 {
			return ReadPropertyMultipleACK{}, fmt.Errorf("%w: invalid object identifier length %d", ErrDecodeFailure, len(objBytes))
		}
		objID := types.ObjectIdentifier(binary.BigEndian.Uint32(objBytes))
		cursor = next

		next, err = expectOpeningTag(payload, cursor, 1)
		if err != nil {
			return ReadPropertyMultipleACK{}, err
		}
		cursor = next

		res := ReadAccessResult{ObjectIdentifier: objID, Results: make([]ReadPropertyResult, 0)}

		for {
			if isClosingTagAt(payload, cursor, 1) {
				cursor += 1
				break
			}

			result, nextCursor, err := decodeReadPropertyResult(payload, cursor)
			if err != nil {
				return ReadPropertyMultipleACK{}, err
			}
			res.Results = append(res.Results, result)
			cursor = nextCursor
		}

		ack.Results = append(ack.Results, res)
	}

	return ack, nil
}

func decodeReadPropertyResult(payload []byte, offset int) (ReadPropertyResult, int, error) {
	var out ReadPropertyResult

	_, propBytes, next, err := decodeExpectedContextPrimitive(payload, offset, 2)
	if err != nil {
		return ReadPropertyResult{}, offset, err
	}
	propID, err := decodeUnsigned(propBytes)
	if err != nil {
		return ReadPropertyResult{}, offset, fmt.Errorf("%w: invalid property identifier: %v", ErrDecodeFailure, err)
	}
	out.PropertyIdentifier = types.PropertyIdentifier(propID)
	offset = next

	if looksLikeContextPrimitiveTag(payload[offset], 3) {
		_, idxBytes, next, err := decodeExpectedContextPrimitive(payload, offset, 3)
		if err != nil {
			return ReadPropertyResult{}, offset, err
		}
		idx, err := decodeUnsigned(idxBytes)
		if err != nil {
			return ReadPropertyResult{}, offset, fmt.Errorf("%w: invalid array index: %v", ErrDecodeFailure, err)
		}
		out.ArrayIndex = &idx
		offset = next
	}

	if isOpeningTagAt(payload, offset, 4) {
		next, value, err := decodeTaggedBody(payload, offset, 4)
		if err != nil {
			return ReadPropertyResult{}, offset, err
		}
		out.PropertyValue = value
		return out, next, nil
	}

	if isOpeningTagAt(payload, offset, 5) {
		next, value, err := decodeTaggedBody(payload, offset, 5)
		if err != nil {
			return ReadPropertyResult{}, offset, err
		}
		out.Error = value
		return out, next, nil
	}

	return ReadPropertyResult{}, offset, fmt.Errorf("%w: expected opening tag 4 or 5", ErrDecodeFailure)
}

func decodeTaggedBody(payload []byte, offset int, tagNumber bacencoding.AppTag) (int, []byte, error) {
	next, err := expectOpeningTag(payload, offset, tagNumber)
	if err != nil {
		return offset, nil, err
	}

	start := next
	stack := []bacencoding.AppTag{tagNumber}
	cursor := next
	for cursor < len(payload) {
		tag, hdrLen, valueLen, err := bacencoding.ParseTag(payload[cursor:])
		if err != nil {
			return offset, nil, fmt.Errorf("%w: decode tagged body: %v", ErrDecodeFailure, err)
		}
		switch {
		case tag.Opening:
			stack = append(stack, tag.TagNumber)
			cursor += hdrLen
		case tag.Closing:
			if len(stack) == 0 {
				return offset, nil, fmt.Errorf("%w: unbalanced closing tag", ErrDecodeFailure)
			}
			expected := stack[len(stack)-1]
			if expected != tag.TagNumber {
				return offset, nil, fmt.Errorf("%w: mismatched closing tag, expected %d got %d", ErrDecodeFailure, expected, tag.TagNumber)
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return cursor + hdrLen, slices.Clone(payload[start:cursor]), nil
			}
			cursor += hdrLen
		default:
			cursor += hdrLen + valueLen
		}
	}

	return offset, nil, fmt.Errorf("%w: missing closing tag %d", ErrDecodeFailure, tagNumber)
}

// WritePropertyRequest is the typed request payload for WriteProperty.
type WritePropertyRequest struct {
	ObjectIdentifier   types.ObjectIdentifier
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	PropertyValue      []byte
	Priority           *uint8
}

// NewWritePropertyRequest constructs a validated WritePropertyRequest.
func NewWritePropertyRequest(
	objectIdentifier types.ObjectIdentifier,
	propertyIdentifier types.PropertyIdentifier,
	arrayIndex *uint32,
	propertyValue []byte,
	priority *uint8,
) (WritePropertyRequest, error) {
	req := WritePropertyRequest{
		ObjectIdentifier:   objectIdentifier,
		PropertyIdentifier: propertyIdentifier,
		ArrayIndex:         arrayIndex,
		PropertyValue:      slices.Clone(propertyValue),
		Priority:           priority,
	}
	if err := validateWritePropertyRequest(req); err != nil {
		return WritePropertyRequest{}, err
	}
	return req, nil
}

func validateWritePropertyRequest(req WritePropertyRequest) error {
	if !req.ObjectIdentifier.ObjectType().Valid() {
		return bacneterrors.NewValidationError("object identifier", req.ObjectIdentifier, ErrEncodeFailure)
	}
	if len(req.PropertyValue) == 0 {
		return bacneterrors.NewValidationError("property value", len(req.PropertyValue), ErrEncodeFailure)
	}
	if req.Priority != nil {
		if *req.Priority == 0 || *req.Priority > 16 {
			return bacneterrors.NewValidationError("priority", *req.Priority, ErrEncodeFailure)
		}
	}
	return nil
}

func (c *clientImpl) WriteProperty(ctx context.Context, dst netprim.Address, req WritePropertyRequest) error {
	if err := validateWritePropertyRequest(req); err != nil {
		return err
	}

	payload, err := encodeWritePropertyRequestPayload(req)
	if err != nil {
		return err
	}

	ackPayload, err := c.InvokeConfirmedRaw(ctx, dst, ServiceChoiceWriteProperty, payload)
	if err != nil {
		return classifyRemoteAPDUError(ServiceChoiceWriteProperty, err)
	}

	if len(ackPayload) != 0 {
		return fmt.Errorf("%w: write-property expected simple-ack payload to be empty", ErrDecodeFailure)
	}

	return nil
}

func encodeWritePropertyRequestPayload(req WritePropertyRequest) ([]byte, error) {
	objRaw := uint32(req.ObjectIdentifier)
	out := make([]byte, 0, 32+len(req.PropertyValue))

	out = append(out, encodeContextPrimitive(0, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
	out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.PropertyIdentifier)))...)
	if req.ArrayIndex != nil {
		out = append(out, encodeContextPrimitive(2, encodeUnsigned(*req.ArrayIndex))...)
	}
	out = append(out, encodeOpeningTag(3)...)
	out = append(out, req.PropertyValue...)
	out = append(out, encodeClosingTag(3)...)
	if req.Priority != nil {
		out = append(out, encodeContextPrimitive(4, encodeUnsigned(uint32(*req.Priority)))...)
	}

	return out, nil
}

// PropertyValueWrite identifies one property write operation.
type PropertyValueWrite struct {
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	PropertyValue      []byte
	Priority           *uint8
}

// WriteAccessSpecification defines one object and its property writes.
type WriteAccessSpecification struct {
	ObjectIdentifier types.ObjectIdentifier
	Values           []PropertyValueWrite
}

// WritePropertyMultipleRequest is the typed request payload for WritePropertyMultiple.
type WritePropertyMultipleRequest struct {
	Writes []WriteAccessSpecification
}

// NewWritePropertyMultipleRequest constructs a validated WritePropertyMultipleRequest.
func NewWritePropertyMultipleRequest(writes []WriteAccessSpecification) (WritePropertyMultipleRequest, error) {
	writesCopy := make([]WriteAccessSpecification, len(writes))
	copy(writesCopy, writes)
	req := WritePropertyMultipleRequest{Writes: writesCopy}
	if err := validateWritePropertyMultipleRequest(req); err != nil {
		return WritePropertyMultipleRequest{}, err
	}
	return req, nil
}

func validateWritePropertyMultipleRequest(req WritePropertyMultipleRequest) error {
	if len(req.Writes) == 0 {
		return bacneterrors.NewValidationError("writes", len(req.Writes), ErrEncodeFailure)
	}

	for i, spec := range req.Writes {
		if !spec.ObjectIdentifier.ObjectType().Valid() {
			return bacneterrors.NewValidationError(fmt.Sprintf("writes[%d].object identifier", i), spec.ObjectIdentifier, ErrEncodeFailure)
		}
		if len(spec.Values) == 0 {
			return bacneterrors.NewValidationError(fmt.Sprintf("writes[%d].values", i), len(spec.Values), ErrEncodeFailure)
		}
		for j, v := range spec.Values {
			if len(v.PropertyValue) == 0 {
				return bacneterrors.NewValidationError(fmt.Sprintf("writes[%d].values[%d].property value", i, j), len(v.PropertyValue), ErrEncodeFailure)
			}
			if v.Priority != nil {
				if *v.Priority == 0 || *v.Priority > 16 {
					return bacneterrors.NewValidationError(fmt.Sprintf("writes[%d].values[%d].priority", i, j), *v.Priority, ErrEncodeFailure)
				}
			}
		}
	}

	return nil
}

func (c *clientImpl) WritePropertyMultiple(ctx context.Context, dst netprim.Address, req WritePropertyMultipleRequest) error {
	if err := validateWritePropertyMultipleRequest(req); err != nil {
		return err
	}

	payload, err := encodeWritePropertyMultipleRequestPayload(req)
	if err != nil {
		return err
	}

	ackPayload, err := c.InvokeConfirmedRaw(ctx, dst, ServiceChoiceWritePropertyMultiple, payload)
	if err != nil {
		return classifyRemoteAPDUError(ServiceChoiceWritePropertyMultiple, err)
	}

	if len(ackPayload) != 0 {
		return fmt.Errorf("%w: write-property-multiple expected simple-ack payload to be empty", ErrDecodeFailure)
	}

	return nil
}

func encodeWritePropertyMultipleRequestPayload(req WritePropertyMultipleRequest) ([]byte, error) {
	out := make([]byte, 0, 64)

	for _, spec := range req.Writes {
		out = append(out, encodeOpeningTag(0)...)
		objRaw := uint32(spec.ObjectIdentifier)
		out = append(out, encodeContextPrimitive(0, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
		out = append(out, encodeOpeningTag(1)...)
		for _, v := range spec.Values {
			out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(v.PropertyIdentifier)))...)
			if v.ArrayIndex != nil {
				out = append(out, encodeContextPrimitive(1, encodeUnsigned(*v.ArrayIndex))...)
			}
			out = append(out, encodeOpeningTag(2)...)
			out = append(out, v.PropertyValue...)
			out = append(out, encodeClosingTag(2)...)
			if v.Priority != nil {
				out = append(out, encodeContextPrimitive(3, encodeUnsigned(uint32(*v.Priority)))...)
			}
		}
		out = append(out, encodeClosingTag(1)...)
		out = append(out, encodeClosingTag(0)...)
	}

	return out, nil
}

func encodeOpeningTag(tagNumber uint8) []byte {
	return bacencoding.EncodeOpeningTag(tagNumber)
}

func encodeClosingTag(tagNumber uint8) []byte {
	return bacencoding.EncodeClosingTag(tagNumber)
}

func isOpeningTagAt(payload []byte, offset int, tagNumber bacencoding.AppTag) bool {
	if offset >= len(payload) {
		return false
	}
	tag, _, _, err := bacencoding.ParseTag(payload[offset:])
	if err != nil {
		return false
	}
	return tag.Opening && tag.TagNumber == tagNumber
}

func isClosingTagAt(payload []byte, offset int, tagNumber bacencoding.AppTag) bool {
	if offset >= len(payload) {
		return false
	}
	tag, _, _, err := bacencoding.ParseTag(payload[offset:])
	if err != nil {
		return false
	}
	return tag.Closing && tag.TagNumber == tagNumber
}

func expectOpeningTag(payload []byte, offset int, tagNumber bacencoding.AppTag) (int, error) {
	next, err := bacencoding.ExpectOpeningTag(payload, offset, tagNumber)
	if err != nil {
		return offset, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}
	return next, nil
}

func expectClosingTag(payload []byte, offset int, tagNumber bacencoding.AppTag) (int, error) {
	next, err := bacencoding.ExpectClosingTag(payload, offset, tagNumber)
	if err != nil {
		return offset, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}
	return next, nil
}

// ReadRangeType selects the requested range variant.
type ReadRangeType uint8

const (
	ReadRangeTypeByPosition ReadRangeType = iota
	ReadRangeTypeBySequenceNumber
	ReadRangeTypeByTime
)

// ReadRangeByPosition requests items relative to an array position.
type ReadRangeByPosition struct {
	ReferenceIndex uint32
	Count          uint16
}

// ReadRangeBySequenceNumber requests items relative to a sequence number.
type ReadRangeBySequenceNumber struct {
	SequenceNumber uint32
	Count          uint16
}

// ReadRangeByTime requests items relative to a reference date-time.
type ReadRangeByTime struct {
	ReferenceTime bacencoding.BACnetDateTime
	Count         uint16
}

// ReadRangeRequest is the typed request payload for ReadRange.
type ReadRangeRequest struct {
	ObjectIdentifier   types.ObjectIdentifier
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	ByPosition         *ReadRangeByPosition
	BySequenceNumber   *ReadRangeBySequenceNumber
	ByTime             *ReadRangeByTime
}

// NewReadRangeRequest constructs a validated ReadRangeRequest.
func NewReadRangeRequest(
	objectIdentifier types.ObjectIdentifier,
	propertyIdentifier types.PropertyIdentifier,
	arrayIndex *uint32,
	byPosition *ReadRangeByPosition,
	bySequenceNumber *ReadRangeBySequenceNumber,
	byTime *ReadRangeByTime,
) (ReadRangeRequest, error) {
	var byTimeCopy *ReadRangeByTime
	if byTime != nil {
		v := *byTime
		byTimeCopy = &v
	}

	req := ReadRangeRequest{
		ObjectIdentifier:   objectIdentifier,
		PropertyIdentifier: propertyIdentifier,
		ArrayIndex:         arrayIndex,
		ByPosition:         byPosition,
		BySequenceNumber:   bySequenceNumber,
		ByTime:             byTimeCopy,
	}
	if err := validateReadRangeRequest(req); err != nil {
		return ReadRangeRequest{}, err
	}
	return req, nil
}

func validateReadRangeRequest(req ReadRangeRequest) error {
	if !req.ObjectIdentifier.ObjectType().Valid() {
		return bacneterrors.NewValidationError("object identifier", req.ObjectIdentifier, ErrEncodeFailure)
	}

	variantCount := 0
	if req.ByPosition != nil {
		variantCount++
		if req.ByPosition.Count == 0 {
			return bacneterrors.NewValidationError("by position count", req.ByPosition.Count, ErrEncodeFailure)
		}
	}
	if req.BySequenceNumber != nil {
		variantCount++
		if req.BySequenceNumber.Count == 0 {
			return bacneterrors.NewValidationError("by sequence number count", req.BySequenceNumber.Count, ErrEncodeFailure)
		}
	}
	if req.ByTime != nil {
		variantCount++
		if req.ByTime.Count == 0 {
			return bacneterrors.NewValidationError("by time count", req.ByTime.Count, ErrEncodeFailure)
		}
	}

	if variantCount != 1 {
		return bacneterrors.NewValidationError("range variant", variantCount, ErrEncodeFailure)
	}

	return nil
}

// ReadRangeACK is the typed ACK payload for ReadRange.
type ReadRangeACK struct {
	ObjectIdentifier   types.ObjectIdentifier
	PropertyIdentifier types.PropertyIdentifier
	ArrayIndex         *uint32
	ResultFlags        []byte
	ItemCount          *uint32
	ItemData           []byte
}

func (c *clientImpl) ReadRange(ctx context.Context, dst netprim.Address, req ReadRangeRequest) (ReadRangeACK, error) {
	if err := validateReadRangeRequest(req); err != nil {
		return ReadRangeACK{}, err
	}

	codec := ConfirmedCodec[ReadRangeRequest, ReadRangeACK]{
		ServiceChoice: ServiceChoiceReadRange,
		EncodeRequest: encodeReadRangeRequestPayload,
		DecodeACK:     decodeReadRangeACKPayload,
	}

	ack, err := InvokeConfirmedTyped(ctx, c, dst, codec, req)
	if err != nil {
		return ReadRangeACK{}, classifyRemoteAPDUError(ServiceChoiceReadRange, err)
	}
	return ack, nil
}

func encodeReadRangeRequestPayload(req ReadRangeRequest) ([]byte, error) {
	objRaw := uint32(req.ObjectIdentifier)
	out := make([]byte, 0, 48)
	out = append(out, encodeContextPrimitive(0, []byte{byte(objRaw >> 24), byte(objRaw >> 16), byte(objRaw >> 8), byte(objRaw)})...)
	out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.PropertyIdentifier)))...)
	if req.ArrayIndex != nil {
		out = append(out, encodeContextPrimitive(2, encodeUnsigned(*req.ArrayIndex))...)
	}

	switch {
	case req.ByPosition != nil:
		out = append(out, encodeOpeningTag(3)...)
		out = append(out, encodeContextPrimitive(0, encodeUnsigned(req.ByPosition.ReferenceIndex))...)
		out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.ByPosition.Count)))...)
		out = append(out, encodeClosingTag(3)...)
	case req.BySequenceNumber != nil:
		out = append(out, encodeOpeningTag(4)...)
		out = append(out, encodeContextPrimitive(0, encodeUnsigned(req.BySequenceNumber.SequenceNumber))...)
		out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.BySequenceNumber.Count)))...)
		out = append(out, encodeClosingTag(4)...)
	case req.ByTime != nil:
		dtBytes, err := bacencoding.EncodeDateTimeValue(req.ByTime.ReferenceTime)
		if err != nil {
			return nil, fmt.Errorf("%w: read-range by-time reference-time: %v", ErrEncodeFailure, err)
		}
		out = append(out, encodeOpeningTag(5)...)
		out = append(out, encodeContextPrimitive(0, dtBytes)...)
		out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(req.ByTime.Count)))...)
		out = append(out, encodeClosingTag(5)...)
	}

	return out, nil
}

func decodeReadRangeACKPayload(payload []byte) (ReadRangeACK, error) {
	res := ReadRangeACK{}
	cursor := 0

	objID, next, err := decodeExpectedContextObjectIdentifier(payload, cursor, 0)
	if err != nil {
		return ReadRangeACK{}, err
	}
	res.ObjectIdentifier = objID
	cursor = next

	_, propBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
	if err != nil {
		return ReadRangeACK{}, err
	}
	propID, err := decodeUnsigned(propBytes)
	if err != nil {
		return ReadRangeACK{}, fmt.Errorf("%w: invalid property identifier: %v", ErrDecodeFailure, err)
	}
	res.PropertyIdentifier = types.PropertyIdentifier(propID)
	cursor = next

	if cursor < len(payload) && looksLikeContextPrimitiveTag(payload[cursor], 2) {
		_, arrBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 2)
		if err != nil {
			return ReadRangeACK{}, err
		}
		idx, err := decodeUnsigned(arrBytes)
		if err != nil {
			return ReadRangeACK{}, fmt.Errorf("%w: invalid array index: %v", ErrDecodeFailure, err)
		}
		res.ArrayIndex = &idx
		cursor = next
	}

	_, flagsBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 3)
	if err != nil {
		return ReadRangeACK{}, err
	}
	res.ResultFlags = slices.Clone(flagsBytes)
	cursor = next

	if cursor < len(payload) && looksLikeContextPrimitiveTag(payload[cursor], 4) {
		_, countBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 4)
		if err != nil {
			return ReadRangeACK{}, err
		}
		count, err := decodeUnsigned(countBytes)
		if err != nil {
			return ReadRangeACK{}, fmt.Errorf("%w: invalid item count: %v", ErrDecodeFailure, err)
		}
		res.ItemCount = &count
		cursor = next
	}

	next, itemData, err := decodeTaggedBody(payload, cursor, 5)
	if err != nil {
		return ReadRangeACK{}, err
	}
	res.ItemData = itemData
	cursor = next

	if cursor != len(payload) {
		return ReadRangeACK{}, fmt.Errorf("%w: trailing bytes in read-range-ack payload", ErrDecodeFailure)
	}

	return res, nil
}
