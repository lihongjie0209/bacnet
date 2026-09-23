package mstp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const MaxDataLength = 501

const (
	FrameToken byte = iota
	FramePollForMaster
	FrameReplyToPollForMaster
	FrameTestRequest
	FrameTestResponse
	FrameDataExpectingReply
	FrameDataNotExpectingReply
	FrameReplyPostponed
)

type Frame struct {
	Type        byte
	Destination byte
	Source      byte
	Data        []byte
}

func EncodeFrame(frame Frame) ([]byte, error) {
	if err := validateFrame(frame, MaxDataLength); err != nil {
		return nil, err
	}
	out := make([]byte, 8+len(frame.Data))
	if len(frame.Data) > 0 {
		out = append(out, 0, 0)
	}
	out[0], out[1] = 0x55, 0xff
	out[2], out[3], out[4] = frame.Type, frame.Destination, frame.Source
	binary.BigEndian.PutUint16(out[5:7], uint16(len(frame.Data)))
	crc := byte(0xff)
	for _, value := range out[2:7] {
		crc = headerCRCUpdate(value, crc)
	}
	out[7] = ^crc
	if len(frame.Data) > 0 {
		copy(out[8:], frame.Data)
		crc := uint16(0xffff)
		for _, value := range frame.Data {
			crc = dataCRCUpdate(value, crc)
		}
		crc = ^crc
		out[len(out)-2], out[len(out)-1] = byte(crc), byte(crc>>8)
	}
	return out, nil
}

func DecodeFrame(raw []byte, maxData int) (Frame, int, error) {
	if len(raw) < 8 {
		return Frame{}, 0, errors.New("truncated MS/TP header")
	}
	if raw[0] != 0x55 || raw[1] != 0xff {
		return Frame{}, 0, errors.New("invalid MS/TP preamble")
	}
	crc := byte(0xff)
	for _, value := range raw[2:8] {
		crc = headerCRCUpdate(value, crc)
	}
	if crc != 0x55 {
		return Frame{}, 0, errors.New("invalid MS/TP header CRC")
	}
	if maxData < 0 || maxData > MaxDataLength {
		maxData = MaxDataLength
	}
	length := int(binary.BigEndian.Uint16(raw[5:7]))
	frame := Frame{Type: raw[2], Destination: raw[3], Source: raw[4]}
	if !validFrameType(frame.Type) || frame.Source == 255 {
		return Frame{}, 0, errors.New("invalid MS/TP frame header")
	}
	if length > maxData {
		return Frame{}, 0, fmt.Errorf("MS/TP data length %d exceeds %d", length, maxData)
	}
	if isControlFrame(frame.Type) && length != 0 {
		return Frame{}, 0, errors.New("MS/TP control frame contains data")
	}
	if frame.Type >= 128 && length < 2 {
		return Frame{}, 0, errors.New("MS/TP proprietary frame is missing vendor identifier")
	}
	total := 8
	if length > 0 {
		total += length + 2
	}
	if len(raw) < total {
		return Frame{}, 0, errors.New("truncated MS/TP data")
	}
	if length > 0 {
		if dataCRC(raw[8:total]) != 0xf0b8 {
			return Frame{}, 0, errors.New("invalid MS/TP data CRC")
		}
		frame.Data = append([]byte(nil), raw[8:8+length]...)
	}
	return frame, total, nil
}

type Decoder struct {
	buffer  []byte
	maxData int
}

func NewDecoder(maxData int) *Decoder {
	if maxData < 1 || maxData > MaxDataLength {
		maxData = MaxDataLength
	}
	return &Decoder{maxData: maxData}
}

func (d *Decoder) Feed(data []byte) []Frame {
	d.buffer = append(d.buffer, data...)
	frames := []Frame{}
	for {
		start := -1
		for index := 0; index+1 < len(d.buffer); index++ {
			if d.buffer[index] == 0x55 && d.buffer[index+1] == 0xff {
				start = index
				break
			}
		}
		if start < 0 {
			if len(d.buffer) > 0 && d.buffer[len(d.buffer)-1] == 0x55 {
				d.buffer = d.buffer[len(d.buffer)-1:]
			} else {
				d.buffer = d.buffer[:0]
			}
			break
		}
		if start > 0 {
			d.buffer = d.buffer[start:]
		}
		frame, consumed, err := DecodeFrame(d.buffer, d.maxData)
		if err != nil {
			if len(d.buffer) < 8 {
				break
			}
			length := int(binary.BigEndian.Uint16(d.buffer[5:7]))
			needed := 8
			if length > 0 {
				needed += length + 2
			}
			if length <= d.maxData && len(d.buffer) < needed {
				break
			}
			d.buffer = d.buffer[1:]
			continue
		}
		frames = append(frames, frame)
		d.buffer = d.buffer[consumed:]
	}
	return frames
}

func validateFrame(frame Frame, maxData int) error {
	if !validFrameType(frame.Type) {
		return fmt.Errorf("reserved MS/TP frame type %d", frame.Type)
	}
	if frame.Source == 255 {
		return errors.New("MS/TP source address cannot be broadcast")
	}
	if len(frame.Data) > maxData {
		return fmt.Errorf("MS/TP data length %d exceeds %d", len(frame.Data), maxData)
	}
	if isControlFrame(frame.Type) && len(frame.Data) != 0 {
		return errors.New("MS/TP control frame must not contain data")
	}
	if frame.Type >= 128 && len(frame.Data) < 2 {
		return errors.New("MS/TP proprietary frame requires vendor identifier")
	}
	return nil
}

func validFrameType(kind byte) bool { return kind <= FrameReplyPostponed || kind >= 128 }

func isControlFrame(kind byte) bool {
	return kind <= FrameReplyToPollForMaster || kind == FrameReplyPostponed
}

func headerCRCUpdate(data, crc byte) byte {
	value := uint16(crc ^ data)
	value = value ^ (value << 1) ^ (value << 2) ^ (value << 3) ^ (value << 4) ^ (value << 5) ^ (value << 6) ^ (value << 7)
	return byte((value & 0xfe) ^ ((value >> 8) & 1))
}

func dataCRCUpdate(data byte, crc uint16) uint16 {
	low := (crc & 0xff) ^ uint16(data)
	return (crc >> 8) ^ (low << 8) ^ (low << 3) ^ (low << 12) ^ (low >> 4) ^ (low & 0x0f) ^ ((low & 0x0f) << 7)
}

func dataCRC(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, value := range data {
		crc = dataCRCUpdate(value, crc)
	}
	return crc
}
