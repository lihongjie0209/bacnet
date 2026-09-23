package schedule

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func u8(v uint8) *uint8    { return &v }
func u16(v uint16) *uint16 { return &v }

func TestBACnetCalendarEntriesGoldenRoundTrip(t *testing.T) {
	entries := []BACnetCalendarEntry{
		{Type: "date", Date: &BACnetCalendarDate{Year: u16(2026), Month: u8(9), Day: u8(22), Weekday: u8(2)}},
		{Type: "dateRange", Start: &BACnetCalendarDate{Month: u8(1), Day: u8(1)}, End: &BACnetCalendarDate{Month: u8(12), Day: u8(31)}},
		{Type: "weekNDay", WeekNDay: &BACnetWeekNDay{Month: u8(13), Week: u8(6), Weekday: u8(1)}},
	}
	raw, err := encodeBACnetCalendarEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x0c, 126, 9, 22, 2, 0x1e, 0xa4, 255, 1, 1, 255, 0xa4, 255, 12, 31, 255, 0x1f, 0x2b, 13, 6, 1}
	if !reflect.DeepEqual(raw, want) {
		t.Fatalf("wire = %x, want %x", raw, want)
	}
	decoded, err := decodeBACnetCalendarEntries(raw, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, entries) {
		t.Fatalf("decoded = %#v, want %#v", decoded, entries)
	}
}

func TestBACnetWeeklyScheduleRoundTrip(t *testing.T) {
	days := make([][]BACnetTimeValue, 7)
	for i := range days {
		days[i] = []BACnetTimeValue{}
	}
	days[0] = []BACnetTimeValue{
		{Time: BACnetTime{Hour: 8}, Value: BACnetScheduleValue{Type: "real", Value: 20.5}},
		{Time: BACnetTime{Hour: 18}, Value: BACnetScheduleValue{Type: "null"}},
	}
	raw, err := encodeBACnetWeeklySchedule(days)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBACnetWeeklySchedule(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, days) {
		t.Fatalf("decoded = %#v, want %#v", decoded, days)
	}
}

func TestBACnetScheduleCodecRejectsMalformedAndOrdering(t *testing.T) {
	days := make([][]BACnetTimeValue, 7)
	for i := range days {
		days[i] = []BACnetTimeValue{}
	}
	days[0] = []BACnetTimeValue{
		{Time: BACnetTime{Hour: 9}, Value: BACnetScheduleValue{Type: "boolean", Value: true}},
		{Time: BACnetTime{Hour: 8}, Value: BACnetScheduleValue{Type: "boolean", Value: false}},
	}
	if _, err := encodeBACnetWeeklySchedule(days); err == nil {
		t.Fatal("want ordering error")
	}
	if _, err := decodeBACnetWeeklySchedule([]byte{0x0e, 0xb4}); err == nil {
		t.Fatal("want truncated error")
	}
	if _, err := encodeBACnetWeeklySchedule(make([][]BACnetTimeValue, 6)); err == nil {
		t.Fatal("want seven-day error")
	}
}

func TestBACnetSpecialEventsRoundTrip(t *testing.T) {
	events := []BACnetSpecialEvent{
		{CalendarEntry: &BACnetCalendarEntry{Type: "weekNDay", WeekNDay: &BACnetWeekNDay{Week: u8(1), Weekday: u8(1)}}, Values: []BACnetTimeValue{{Time: BACnetTime{Hour: 7}, Value: BACnetScheduleValue{Type: "unsigned", Value: float64(1)}}}, Priority: 8},
		{CalendarReference: "calendar:4", Values: []BACnetTimeValue{{Time: BACnetTime{Hour: 9}, Value: BACnetScheduleValue{Type: "raw", Tag: u8(13), RawBase64: base64.StdEncoding.EncodeToString([]byte{0xd1, 3})}}}, Priority: 1},
	}
	raw, err := encodeBACnetSpecialEvents(events)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBACnetSpecialEvents(raw, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, events) {
		t.Fatalf("decoded = %#v, want %#v", decoded, events)
	}
}
