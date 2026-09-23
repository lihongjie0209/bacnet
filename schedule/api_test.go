package schedule_test

import (
	"reflect"
	"testing"

	"github.com/worldiety/bacnet/schedule"
)

func TestPublicCalendarCodecRoundTrip(t *testing.T) {
	year := uint16(2026)
	month := uint8(9)
	day := uint8(24)
	entries := []schedule.BACnetCalendarEntry{{
		Type: "date",
		Date: &schedule.BACnetCalendarDate{Year: &year, Month: &month, Day: &day},
	}}

	raw, err := schedule.EncodeCalendarEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := schedule.DecodeCalendarEntries(raw, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, entries) {
		t.Fatalf("decoded = %#v, want %#v", got, entries)
	}
}

func TestPublicEffectivePeriodAndValueCodecsRoundTrip(t *testing.T) {
	year := uint16(2026)
	month := uint8(9)
	day := uint8(24)
	period := schedule.BACnetEffectivePeriod{
		Start: schedule.BACnetCalendarDate{Year: &year, Month: &month, Day: &day},
		End:   schedule.BACnetCalendarDate{},
	}
	raw, err := schedule.EncodeEffectivePeriod(period)
	if err != nil {
		t.Fatal(err)
	}
	gotPeriod, err := schedule.DecodeEffectivePeriod(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotPeriod, period) {
		t.Fatalf("decoded period = %#v, want %#v", gotPeriod, period)
	}

	wantValue := schedule.BACnetScheduleValue{Type: "characterString", Value: "occupied"}
	raw, err = schedule.EncodeValue(wantValue)
	if err != nil {
		t.Fatal(err)
	}
	gotValue, err := schedule.DecodeValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("decoded value = %#v, want %#v", gotValue, wantValue)
	}
}

func TestPublicWeeklyAndSpecialEventCodecsRoundTrip(t *testing.T) {
	days := make([][]schedule.BACnetTimeValue, 7)
	for i := range days {
		days[i] = []schedule.BACnetTimeValue{}
	}
	days[0] = []schedule.BACnetTimeValue{{
		Time:  schedule.BACnetTime{Hour: 8},
		Value: schedule.BACnetScheduleValue{Type: "boolean", Value: true},
	}}

	raw, err := schedule.EncodeWeeklySchedule(days)
	if err != nil {
		t.Fatal(err)
	}
	gotDays, err := schedule.DecodeWeeklySchedule(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotDays, days) {
		t.Fatalf("decoded days = %#v, want %#v", gotDays, days)
	}

	week := uint8(1)
	weekday := uint8(1)
	events := []schedule.BACnetSpecialEvent{{
		CalendarEntry: &schedule.BACnetCalendarEntry{
			Type:     "weekNDay",
			WeekNDay: &schedule.BACnetWeekNDay{Week: &week, Weekday: &weekday},
		},
		Values:   days[0],
		Priority: 8,
	}}
	raw, err = schedule.EncodeSpecialEvents(events)
	if err != nil {
		t.Fatal(err)
	}
	gotEvents, err := schedule.DecodeSpecialEvents(raw, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotEvents, events) {
		t.Fatalf("decoded events = %#v, want %#v", gotEvents, events)
	}
}
