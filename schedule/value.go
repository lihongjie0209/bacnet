package schedule

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"time"

	bacclient "github.com/worldiety/bacnet/client"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

func bacnetApplicationJSON(value bacencoding.ApplicationValue) any {
	switch v := value.(type) {
	case bacencoding.AppNull:
		return nil
	case bacencoding.AppBoolean:
		return bool(v)
	case bacencoding.AppUnsignedInteger:
		return uint32(v)
	case bacencoding.AppInteger:
		return int32(v)
	case bacencoding.AppReal:
		return float32(v)
	case bacencoding.AppDouble:
		return float64(v)
	case bacencoding.AppOctetString:
		return map[string]any{"type": "octetString", "base64": base64.StdEncoding.EncodeToString(v)}
	case bacencoding.AppCharacterString:
		return string(v)
	case bacencoding.AppBitString:
		return v.Bits
	case bacencoding.AppEnum:
		return map[string]any{"type": "enumerated", "value": uint32(v)}
	case bacencoding.AppDate:
		return fmt.Sprintf("%04d-%02d-%02d", v.Year, v.Month, v.Day)
	case bacencoding.AppTime:
		return fmt.Sprintf("%02d:%02d:%02d.%02d", v.Hour, v.Minute, v.Second, v.Hundredths)
	case bacencoding.AppObjectIdentifier:
		oid := types.ObjectIdentifier(v)
		return fmt.Sprintf("%s:%d", bacclient.ObjectTypeName(oid.ObjectType()), oid.Instance())
	default:
		return fmt.Sprint(v)
	}
}

func number(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("expected number, got %T", value)
	}
}

func encodeBACnetValue(kind string, value any) (bacencoding.ApplicationValue, error) {
	n, err := number(value)
	switch kind {
	case "null":
		return bacencoding.AppNull{}, nil
	case "boolean":
		v, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("boolean requires bool")
		}
		return bacencoding.AppBoolean(v), nil
	case "unsigned", "enumerated":
		if err != nil || n < 0 || n > math.MaxUint32 || n != math.Trunc(n) {
			return nil, fmt.Errorf("%s is out of range", kind)
		}
		if kind == "unsigned" {
			return bacencoding.AppUnsignedInteger(uint32(n)), nil
		}
		return bacencoding.AppEnum(uint32(n)), nil
	case "signed":
		if err != nil || n < math.MinInt32 || n > math.MaxInt32 || n != math.Trunc(n) {
			return nil, fmt.Errorf("signed is out of range")
		}
		return bacencoding.AppInteger(int32(n)), nil
	case "real":
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("invalid real")
		}
		return bacencoding.AppReal(float32(n)), nil
	case "double":
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("invalid double")
		}
		return bacencoding.AppDouble(n), nil
	case "characterString":
		v, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("characterString requires string")
		}
		return bacencoding.AppCharacterString(v), nil
	case "octetString":
		v, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("octetString requires base64 string")
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(v)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return bacencoding.AppOctetString(decoded), nil
	case "bitString":
		raw, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("bitString requires boolean array")
		}
		bits := make([]bool, len(raw))
		for i, item := range raw {
			bits[i], ok = item.(bool)
			if !ok {
				return nil, fmt.Errorf("bitString item %d requires bool", i)
			}
		}
		return bacencoding.AppBitString{Bits: bits}, nil
	case "objectIdentifier":
		v, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("objectIdentifier requires string")
		}
		obj, parseErr := bacclient.ParseObject(v)
		if parseErr != nil {
			return nil, parseErr
		}
		return bacencoding.AppObjectIdentifier(obj.OID()), nil
	case "date":
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("date requires YYYY-MM-DD string")
		}
		parsed, parseErr := time.Parse("2006-01-02", text)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid date: %w", parseErr)
		}
		return bacencoding.AppDate{Year: uint16(parsed.Year()), Month: uint8(parsed.Month()), Day: uint8(parsed.Day()), Weekday: uint8(parsed.Weekday()+6)%7 + 1}, nil
	case "time":
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("time requires HH:MM:SS or HH:MM:SS.hh string")
		}
		var parsed time.Time
		var parseErr error
		for _, layout := range []string{"15:04:05.00", "15:04:05"} {
			parsed, parseErr = time.Parse(layout, text)
			if parseErr == nil {
				break
			}
		}
		if parseErr != nil {
			return nil, fmt.Errorf("invalid time: %w", parseErr)
		}
		return bacencoding.AppTime{Hour: uint8(parsed.Hour()), Minute: uint8(parsed.Minute()), Second: uint8(parsed.Second()), Hundredths: uint8(parsed.Nanosecond() / 10_000_000)}, nil
	default:
		return nil, fmt.Errorf("unsupported BACnet type %q", kind)
	}
}
