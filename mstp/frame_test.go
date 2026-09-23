package mstp

import (
	"bytes"
	"testing"
)

func TestTokenAnnexGGolden(t *testing.T) {
	frame, err := EncodeFrame(Frame{Type: FrameToken, Destination: 0x10, Source: 0x05})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x55, 0xff, 0x00, 0x10, 0x05, 0x00, 0x00, 0x8c}
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame=%x want=%x", frame, want)
	}
	decoded, consumed, err := DecodeFrame(frame, MaxDataLength)
	if err != nil || consumed != len(frame) || decoded.Type != FrameToken || decoded.Destination != 0x10 || decoded.Source != 0x05 || len(decoded.Data) != 0 {
		t.Fatalf("decoded=%+v consumed=%d err=%v", decoded, consumed, err)
	}
}

func TestDataFrameRoundTrip(t *testing.T) {
	want := Frame{Type: FrameDataExpectingReply, Destination: 7, Source: 3, Data: []byte{0x01, 0x20, 0xff, 0x00, 0x7e}}
	raw, err := EncodeFrame(want)
	if err != nil {
		t.Fatal(err)
	}
	got, consumed, err := DecodeFrame(raw, MaxDataLength)
	if err != nil || consumed != len(raw) || got.Type != want.Type || got.Destination != want.Destination || got.Source != want.Source || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("got=%+v consumed=%d error=%v", got, consumed, err)
	}
	got.Data[0] = 0
	if raw[8] != want.Data[0] {
		t.Fatal("decoded data aliases wire")
	}
}

func TestFrameRejectsMalformed(t *testing.T) {
	valid, _ := EncodeFrame(Frame{Type: FrameDataNotExpectingReply, Destination: 1, Source: 2, Data: []byte{1, 2, 3}})
	tests := [][]byte{nil, {0x55}, {0x55, 0}, append([]byte(nil), valid[:7]...)}
	badHeader := bytes.Clone(valid)
	badHeader[7] ^= 1
	tests = append(tests, badHeader)
	badData := bytes.Clone(valid)
	badData[8] ^= 1
	tests = append(tests, badData)
	for index, raw := range tests {
		if _, _, err := DecodeFrame(raw, MaxDataLength); err == nil {
			t.Fatalf("case %d accepted %x", index, raw)
		}
	}
	for _, frame := range []Frame{
		{Type: 8, Destination: 1, Source: 2},
		{Type: FrameToken, Destination: 1, Source: 2, Data: []byte{1}},
		{Type: 128, Destination: 1, Source: 2, Data: []byte{1}},
		{Type: FrameDataNotExpectingReply, Destination: 1, Source: 255},
	} {
		if _, err := EncodeFrame(frame); err == nil {
			t.Fatalf("accepted invalid frame %+v", frame)
		}
	}
}

func TestDecoderRecoversFromNoiseAndPartialFrames(t *testing.T) {
	first, _ := EncodeFrame(Frame{Type: FramePollForMaster, Destination: 4, Source: 3})
	second, _ := EncodeFrame(Frame{Type: FrameDataNotExpectingReply, Destination: 255, Source: 3, Data: []byte{9}})
	decoder := NewDecoder(MaxDataLength)
	if frames := decoder.Feed(append([]byte{1, 2, 0x55, 3}, first[:5]...)); len(frames) != 0 {
		t.Fatalf("partial emitted %+v", frames)
	}
	frames := decoder.Feed(append(first[5:], second...))
	if len(frames) != 2 || frames[0].Type != FramePollForMaster || frames[1].Data[0] != 9 {
		t.Fatalf("frames=%+v", frames)
	}
}

func FuzzFrameDecoder(f *testing.F) {
	f.Add([]byte{0x55, 0xff, 0, 0x10, 5, 0, 0, 0x8c})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) { _ = NewDecoder(MaxDataLength).Feed(raw) })
}
