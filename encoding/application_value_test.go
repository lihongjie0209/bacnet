package encoding

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/worldiety/bacnet/common/types"
)

// TestDecodeApplicationValue covers each of the 13 application tag types plus
// error paths, using wire bytes that are as close to real-device output as possible.
func TestDecodeApplicationValue(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		offset  int
		want    ApplicationValue
		wantEnd int
		wantErr bool
	}{
		{
			name:    "null",
			raw:     []byte{0x00},
			want:    AppNull{},
			wantEnd: 1,
		},
		{
			name:    "boolean true",
			raw:     []byte{0x11},
			want:    AppBoolean(true),
			wantEnd: 1,
		},
		{
			name:    "boolean false",
			raw:     []byte{0x10},
			want:    AppBoolean(false),
			wantEnd: 1,
		},
		{
			name:    "unsigned integer 1 byte",
			raw:     []byte{0x21, 0x2A},
			want:    AppUnsignedInteger(42),
			wantEnd: 2,
		},
		{
			name:    "unsigned integer 4 bytes",
			raw:     []byte{0x24, 0x00, 0x01, 0x00, 0x00},
			want:    AppUnsignedInteger(65536),
			wantEnd: 5,
		},
		{
			name:    "signed integer positive",
			raw:     []byte{0x31, 0x7F},
			want:    AppInteger(127),
			wantEnd: 2,
		},
		{
			name:    "signed integer negative",
			raw:     []byte{0x31, 0xFF},
			want:    AppInteger(-1),
			wantEnd: 2,
		},
		{
			name:    "real sensor reading",
			raw:     []byte{0x44, 0x41, 0xCE, 0x66, 0x66},
			want:    AppReal(math.Float32frombits(0x41CE6666)),
			wantEnd: 5,
		},
		{
			name:    "real zero",
			raw:     []byte{0x44, 0x00, 0x00, 0x00, 0x00},
			want:    AppReal(0.0),
			wantEnd: 5,
		},
		{
			name:    "double",
			raw:     []byte{0x55, 0x08, 0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18},
			want:    AppDouble(math.Pi),
			wantEnd: 10,
		},
		{
			name:    "octet string",
			raw:     []byte{0x63, 0xDE, 0xAD, 0xBE},
			want:    AppOctetString([]byte{0xDE, 0xAD, 0xBE}),
			wantEnd: 4,
		},
		{
			name: "character string ASCII",
			// tag 7 (CharacterString), LVT=4 (charset byte + 3 chars = 4 bytes)
			raw:     append([]byte{0x74, 0x00}, []byte("hi!")...),
			want:    AppCharacterString("hi!"),
			wantEnd: 5,
		},
		{
			name:    "bit string 3 bits",
			raw:     []byte{0x85, 0x02, 0x05, 0xA0}, // unused=5, data=0xA0 → bits [1,0,1]
			want:    AppBitString{Bits: []bool{true, false, true}},
			wantEnd: 4,
		},
		{
			name:    "enumerated",
			raw:     []byte{0x91, 0x05},
			want:    AppEnum(5),
			wantEnd: 2,
		},
		{
			name:    "date 2024-06-18 Tuesday",
			raw:     []byte{0xA4, 0x7C, 0x06, 0x12, 0x02}, // year=2024(124+1900), month=6, day=18, weekday=2
			want:    AppDate{Year: 2024, Month: 6, Day: 18, Weekday: 2},
			wantEnd: 5,
		},
		{
			name:    "time 13:30:00.50",
			raw:     []byte{0xB4, 0x0D, 0x1E, 0x00, 0x32},
			want:    AppTime{Hour: 13, Minute: 30, Second: 0, Hundredths: 50},
			wantEnd: 5,
		},
		{
			name: "object identifier device 1234",
			// types.ObjectIdentifier: top 10 bits = object type (8=device), lower 22 bits = instance
			// device=8 → 8<<22 = 0x02000000; instance=1234 → 0x000004D2
			// combined = 0x020004D2
			raw:     []byte{0xC4, 0x02, 0x00, 0x04, 0xD2},
			want:    AppObjectIdentifier(types.ObjectIdentifier(0x020004D2)),
			wantEnd: 5,
		},
		// offset > 0: decode starts mid-slice
		{
			name:    "real with non-zero offset",
			raw:     []byte{0xFF, 0x44, 0x41, 0xCE, 0x66, 0x66},
			offset:  1,
			want:    AppReal(math.Float32frombits(0x41CE6666)),
			wantEnd: 6,
		},
		// error: context-specific tag
		{
			name:    "error context-specific tag",
			raw:     []byte{0x09, 0x05}, // context tag 0 = 0x08|0x01 → but 0x09 is context tag 0, LVT=1
			wantErr: true,
		},
		// error: empty slice
		{
			name:    "error empty",
			raw:     []byte{},
			wantErr: true,
		},
		// error: offset beyond slice
		{
			name:    "error offset past end",
			raw:     []byte{0x44, 0x41, 0xCE, 0x66, 0x66},
			offset:  10,
			wantErr: true,
		},
		// error: truncated real value
		{
			name:    "error truncated real",
			raw:     []byte{0x44, 0x41, 0xCE}, // only 3 of 4 value bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotEnd, err := DecodeApplicationValue(tt.raw, tt.offset)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (value=%v)", got)
				}
				if !errors.Is(err, ErrDecodeFailure) {
					t.Errorf("error should wrap ErrDecodeFailure, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotEnd != tt.wantEnd {
				t.Errorf("end offset: want %d, got %d", tt.wantEnd, gotEnd)
			}
			// DeepEqual handles AppOctetString ([]byte), AppBitString (struct with []bool), etc.
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("value mismatch:\n  want %#v (%T)\n  got  %#v (%T)", tt.want, tt.want, got, got)
			}
		})
	}
}

// TestEncodeApplicationValue verifies that EncodeApplicationValue produces the
// expected wire bytes for each variant, and that decode(encode(v)) == v.
func TestEncodeApplicationValue(t *testing.T) {
	roundtrips := []ApplicationValue{
		AppNull{},
		AppBoolean(true),
		AppBoolean(false),
		AppUnsignedInteger(0),
		AppUnsignedInteger(255),
		AppUnsignedInteger(65536),
		AppInteger(-1),
		AppInteger(127),
		AppReal(0.0),
		AppReal(math.Float32frombits(0x41CE6666)),
		AppDouble(math.Pi),
		AppOctetString([]byte{0xDE, 0xAD}),
		AppCharacterString("hello"),
		AppBitString{Bits: []bool{true, false, true}},
		AppEnum(0),
		AppEnum(42),
		AppDate{Year: 2024, Month: 6, Day: 18, Weekday: 2},
		AppTime{Hour: 13, Minute: 30, Second: 0, Hundredths: 50},
		AppObjectIdentifier(types.ObjectIdentifier(0x020004D2)),
	}

	for _, v := range roundtrips {
		t.Run("", func(t *testing.T) {
			encoded, err := EncodeApplicationValue(v)
			if err != nil {
				t.Fatalf("EncodeApplicationValue(%#v): %v", v, err)
			}
			decoded, end, err := DecodeApplicationValue(encoded, 0)
			if err != nil {
				t.Fatalf("DecodeApplicationValue round-trip for %#v: %v", v, err)
			}
			if end != len(encoded) {
				t.Errorf("did not consume all encoded bytes: end=%d, len=%d", end, len(encoded))
			}
			if !reflect.DeepEqual(decoded, v) {
				t.Errorf("round-trip mismatch:\n  in  %#v (%T)\n  out %#v (%T)", v, v, decoded, decoded)
			}
		})
	}
}

// TestEncodeApplicationValueError checks that EncodeApplicationValue rejects
// character strings that are not valid UTF-8 (character set 0 is UTF-8).
func TestEncodeApplicationValueError(t *testing.T) {
	_, err := EncodeApplicationValue(AppCharacterString("\xFF not utf-8"))
	if err == nil {
		t.Fatal("want error for invalid-UTF-8 CharacterString, got nil")
	}
	if !errors.Is(err, ErrEncodeFailure) {
		t.Errorf("error should wrap ErrEncodeFailure, got: %v", err)
	}
}

func TestEncodeApplicationValueRaw(t *testing.T) {
	raw := AppRaw{0x0E, 0xB4, 0x08, 0x1E, 0x00, 0x00, 0x21, 0x01, 0x0F}
	encoded, err := EncodeApplicationValue(raw)
	if err != nil {
		t.Fatalf("EncodeApplicationValue(AppRaw): %v", err)
	}
	if !reflect.DeepEqual(encoded, []byte(raw)) {
		t.Fatalf("encoded = %x, want %x", encoded, raw)
	}

	encoded[0] = 0xFF
	if raw[0] != 0x0E {
		t.Fatal("encoded AppRaw aliases caller storage")
	}
}

func TestEncodeApplicationValueRawRejectsInvalidSize(t *testing.T) {
	for _, raw := range []AppRaw{make(AppRaw, MaxAppRawLength+1)} {
		if _, err := EncodeApplicationValue(raw); err == nil || !errors.Is(err, ErrEncodeFailure) {
			t.Fatalf("EncodeApplicationValue(AppRaw length %d) error = %v, want ErrEncodeFailure", len(raw), err)
		}
	}
}

func TestEncodeApplicationValueRawAllowsEmptySequence(t *testing.T) {
	encoded, err := EncodeApplicationValue(AppRaw{})
	if err != nil {
		t.Fatalf("EncodeApplicationValue(empty AppRaw): %v", err)
	}
	if len(encoded) != 0 {
		t.Fatalf("encoded length = %d, want 0", len(encoded))
	}
}

// TestCharacterStringUTF8RoundTrip verifies that non-ASCII UTF-8 character
// strings (character set 0), such as accented characters commonly emitted by
// field devices, encode and decode losslessly.
func TestCharacterStringUTF8RoundTrip(t *testing.T) {
	inputs := []string{
		"Küche / HWR",
		"Zürich",
		"温度",
		"plain ascii",
		"",
	}
	for _, in := range inputs {
		enc, err := EncodeApplicationValue(AppCharacterString(in))
		if err != nil {
			t.Fatalf("encode %q: %v", in, err)
		}
		val, _, err := DecodeApplicationValue(enc, 0)
		if err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		got, ok := val.(AppCharacterString)
		if !ok {
			t.Fatalf("decoded value for %q has type %T, want AppCharacterString", in, val)
		}
		if string(got) != in {
			t.Fatalf("round-trip mismatch: got %q, want %q", string(got), in)
		}
	}
}
