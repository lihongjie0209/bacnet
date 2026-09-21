package encoding

import (
	"fmt"
	"slices"

	"github.com/worldiety/bacnet/common/types"
)

// AppTag is the BACnet application tag number (clause 20.2, Table 20-1).
type AppTag uint32

const (
	AppTagNull             AppTag = 0
	AppTagBoolean          AppTag = 1
	AppTagUnsignedInteger  AppTag = 2
	AppTagInteger          AppTag = 3
	AppTagReal             AppTag = 4
	AppTagDouble           AppTag = 5
	AppTagOctetString      AppTag = 6
	AppTagCharacterString  AppTag = 7
	AppTagBitString        AppTag = 8
	AppTagEnum             AppTag = 9
	AppTagDate             AppTag = 10
	AppTagTime             AppTag = 11
	AppTagObjectIdentifier AppTag = 12
)

// ApplicationValue is a sealed interface representing any of the 13 BACnet
// application primitive types. Use a type switch to extract the concrete value:
//
//	switch v := val.(type) {
//	case encoding.AppReal:
//	    fmt.Println(float32(v))
//	case encoding.AppUnsignedInteger:
//	    fmt.Println(uint32(v))
//	// ...
//	}
type ApplicationValue interface {
	applicationValue()
}

// MaxAppRawLength bounds a pre-encoded complex property value. BACnet APDUs
// impose tighter negotiated limits; this guard prevents accidental unbounded
// allocations before those transport limits are applied.
const MaxAppRawLength = 65535

// AppRaw is a complete, pre-encoded BACnet property value. It is intended for
// constructed and sequence-valued properties that cannot be represented by a
// single application primitive. Callers must validate the property's exact
// ASN.1 shape before constructing AppRaw.
type AppRaw []byte

func (AppRaw) applicationValue() {}

// AppNull represents a BACnet Null value (application tag 0).
type AppNull struct{}

func (AppNull) applicationValue() {}

// AppBoolean represents a BACnet Boolean value (application tag 1).
type AppBoolean bool

func (AppBoolean) applicationValue() {}

// AppUnsignedInteger represents a BACnet Unsigned Integer value (application tag 2).
// The wire encoding is 1–4 bytes; values are widened to uint32.
type AppUnsignedInteger uint32

func (AppUnsignedInteger) applicationValue() {}

// AppInteger represents a BACnet Signed Integer value (application tag 3).
type AppInteger int32

func (AppInteger) applicationValue() {}

// AppReal represents a BACnet Real value (application tag 4, IEEE 754 single-precision).
type AppReal float32

func (AppReal) applicationValue() {}

// AppDouble represents a BACnet Double Precision value (application tag 5, IEEE 754 double-precision).
type AppDouble float64

func (AppDouble) applicationValue() {}

// AppOctetString represents a BACnet Octet String value (application tag 6).
type AppOctetString []byte

func (AppOctetString) applicationValue() {}

// AppCharacterString represents a BACnet Character String value (application tag 7).
// Decoding accepts the standard character sets (UTF-8, ISO-8859-1, UCS-2/UTF-16BE
// and UCS-4/UTF-32BE) and yields a UTF-8 Go string; encoding always emits
// character set 0 (UTF-8).
type AppCharacterString string

func (AppCharacterString) applicationValue() {}

// AppBitString represents a BACnet Bit String value (application tag 8).
type AppBitString struct {
	// Bits holds the bit values in transmission order (index 0 = most significant bit of wire byte 1).
	Bits []bool
}

func (AppBitString) applicationValue() {}

// AppEnum represents a BACnet Enumerated value (application tag 9).
type AppEnum uint32

func (AppEnum) applicationValue() {}

// AppDate represents a BACnet Date value (application tag 10).
type AppDate struct {
	// Year is the full year (e.g. 2024). Use BACnetDateUnspecified (255) for "any year".
	Year uint16
	// Month is 1–12. Use BACnetDateUnspecified for "any month".
	Month uint8
	// Day is 1–31. Use BACnetDateUnspecified for "any day".
	Day uint8
	// Weekday is 1 (Monday) through 7 (Sunday). Use BACnetDateUnspecified for "any weekday".
	Weekday uint8
}

func (AppDate) applicationValue() {}

// AppTime represents a BACnet Time value (application tag 11).
type AppTime struct {
	// Hour is 0–23. Use BACnetTimeUnspecified (255) for "any hour".
	Hour uint8
	// Minute is 0–59. Use BACnetTimeUnspecified for "any minute".
	Minute uint8
	// Second is 0–59. Use BACnetTimeUnspecified for "any second".
	Second uint8
	// Hundredths is 0–99. Use BACnetTimeUnspecified for "any hundredths".
	Hundredths uint8
}

func (AppTime) applicationValue() {}

// AppObjectIdentifier represents a BACnet Object Identifier value (application tag 12).
type AppObjectIdentifier types.ObjectIdentifier

func (AppObjectIdentifier) applicationValue() {}

// DecodeApplicationValue decodes a single BACnet application-tagged TLV starting at
// offset in raw. It returns the decoded ApplicationValue, the new offset (after the
// consumed TLV bytes), and any error.
//
// Returns ErrDecodeFailure-wrapped errors for:
//   - context-specific tags (use DecodeExpectedContextPrimitive instead)
//   - unknown tag numbers (> 12)
//   - malformed or truncated data
func DecodeApplicationValue(raw []byte, offset int) (ApplicationValue, int, error) {
	if offset >= len(raw) {
		return nil, offset, fmt.Errorf("%w: no bytes at offset %d", ErrDecodeFailure, offset)
	}

	tag, hLen, vLen, err := ParseTag(raw[offset:])
	if err != nil {
		return nil, offset, fmt.Errorf("%w: %v", ErrDecodeFailure, err)
	}

	if tag.ContextSpecific {
		return nil, offset, fmt.Errorf("%w: expected application tag, got context-specific tag %d", ErrDecodeFailure, tag.TagNumber)
	}

	// value bytes (empty for Null, Boolean, and zero-length strings)
	valueStart := offset + hLen
	valueEnd := valueStart + vLen
	vBytes := raw[valueStart:valueEnd]

	switch tag.TagNumber {
	case AppTagNull:
		return AppNull{}, valueEnd, nil

	case AppTagBoolean:
		// Boolean is special: the LVT nibble carries the value directly; no value bytes follow.
		// ParseTag returns vLen==0 and leaves the value in the original LVT nibble.
		// We recover it from the raw tag byte.
		lvt := raw[offset] & 0x07
		return AppBoolean(lvt != 0), valueEnd, nil

	case AppTagUnsignedInteger:
		v, err := DecodeUnsigned(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: unsigned integer: %v", ErrDecodeFailure, err)
		}
		return AppUnsignedInteger(v), valueEnd, nil

	case AppTagInteger:
		v, err := DecodeSigned(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: signed integer: %v", ErrDecodeFailure, err)
		}
		return AppInteger(v), valueEnd, nil

	case AppTagReal:
		v, err := DecodeReal(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: real: %v", ErrDecodeFailure, err)
		}
		return AppReal(v), valueEnd, nil

	case AppTagDouble:
		v, err := DecodeDouble(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: double: %v", ErrDecodeFailure, err)
		}
		return AppDouble(v), valueEnd, nil

	case AppTagOctetString:
		return AppOctetString(DecodeOctetStringValue(vBytes)), valueEnd, nil

	case AppTagCharacterString:
		v, err := DecodeCharacterStringValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: character string: %v", ErrDecodeFailure, err)
		}
		return AppCharacterString(v), valueEnd, nil

	case AppTagBitString:
		v, err := DecodeBitStringValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: bit string: %v", ErrDecodeFailure, err)
		}
		bits := make([]bool, len(v.Bits))
		copy(bits, v.Bits)
		return AppBitString{Bits: bits}, valueEnd, nil

	case AppTagEnum:
		v, err := DecodeEnumeratedValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: enumerated: %v", ErrDecodeFailure, err)
		}
		return AppEnum(v), valueEnd, nil

	case AppTagDate:
		v, err := DecodeDateValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: date: %v", ErrDecodeFailure, err)
		}
		return AppDate{Year: v.Year, Month: v.Month, Day: v.Day, Weekday: v.Weekday}, valueEnd, nil

	case AppTagTime:
		v, err := DecodeTimeValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: time: %v", ErrDecodeFailure, err)
		}
		return AppTime{Hour: v.Hour, Minute: v.Minute, Second: v.Second, Hundredths: v.Hundredths}, valueEnd, nil

	case AppTagObjectIdentifier:
		v, err := DecodeObjectIdentifierValue(vBytes)
		if err != nil {
			return nil, offset, fmt.Errorf("%w: object-identifier: %v", ErrDecodeFailure, err)
		}
		return AppObjectIdentifier(v), valueEnd, nil

	default:
		return nil, offset, fmt.Errorf("%w: unknown application tag number %d", ErrDecodeFailure, tag.TagNumber)
	}
}

// EncodeApplicationValue encodes an ApplicationValue into its BACnet wire representation
// (tag byte(s) + value bytes). The returned slice is newly allocated and caller-owned.
func EncodeApplicationValue(v ApplicationValue) ([]byte, error) {
	switch val := v.(type) {
	case AppRaw:
		if len(val) > MaxAppRawLength {
			return nil, fmt.Errorf("%w: raw property value length %d must not exceed %d", ErrEncodeFailure, len(val), MaxAppRawLength)
		}
		return slices.Clone(val), nil

	case AppNull:
		return EncodeNull(), nil

	case AppBoolean:
		return EncodeBoolean(bool(val)), nil

	case AppUnsignedInteger:
		return EncodeApplicationPrimitive(uint8(AppTagUnsignedInteger), EncodeUnsigned(uint32(val))), nil

	case AppInteger:
		return EncodeApplicationPrimitive(uint8(AppTagInteger), EncodeSigned(int32(val))), nil

	case AppReal:
		return EncodeApplicationPrimitive(uint8(AppTagReal), EncodeReal(float32(val))), nil

	case AppDouble:
		return EncodeApplicationPrimitive(uint8(AppTagDouble), EncodeDouble(float64(val))), nil

	case AppOctetString:
		return EncodeApplicationPrimitive(uint8(AppTagOctetString), EncodeOctetStringValue([]byte(val))), nil

	case AppCharacterString:
		vBytes, err := EncodeCharacterStringValue(string(val))
		if err != nil {
			return nil, fmt.Errorf("%w: character string: %v", ErrEncodeFailure, err)
		}
		return EncodeApplicationPrimitive(uint8(AppTagCharacterString), vBytes), nil

	case AppBitString:
		return EncodeApplicationPrimitive(uint8(AppTagBitString), EncodeBitStringValue(BitString{Bits: val.Bits})), nil

	case AppEnum:
		return EncodeApplicationPrimitive(uint8(AppTagEnum), EncodeEnumeratedValue(uint32(val))), nil

	case AppDate:
		vBytes, err := EncodeDateValue(BACnetDate{Year: val.Year, Month: val.Month, Day: val.Day, Weekday: val.Weekday})
		if err != nil {
			return nil, fmt.Errorf("%w: date: %v", ErrEncodeFailure, err)
		}
		return EncodeApplicationPrimitive(uint8(AppTagDate), vBytes), nil

	case AppTime:
		vBytes := EncodeTimeValue(BACnetTime{Hour: val.Hour, Minute: val.Minute, Second: val.Second, Hundredths: val.Hundredths})
		return EncodeApplicationPrimitive(uint8(AppTagTime), vBytes), nil

	case AppObjectIdentifier:
		return EncodeApplicationPrimitive(uint8(AppTagObjectIdentifier), EncodeObjectIdentifierValue(types.ObjectIdentifier(val))), nil

	default:
		return nil, fmt.Errorf("%w: unknown ApplicationValue type %T", ErrEncodeFailure, v)
	}
}
