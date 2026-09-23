package schedule

import (
	"encoding/base64"
	"errors"
	"fmt"

	bacclient "github.com/worldiety/bacnet/client"
	bacencoding "github.com/worldiety/bacnet/encoding"
)

const (
	maxBACnetScheduleValues  = 1024
	maxBACnetCalendarEntries = 10_000
)

func encodeBACnetDate(date BACnetCalendarDate) ([]byte, error) {
	year := uint16(255)
	if date.Year != nil {
		if *date.Year < 1900 || *date.Year > 2154 {
			return nil, errors.New("BACnet date year must be 1900..2154 or wildcard")
		}
		year = *date.Year - 1900
	}
	component := func(name string, value *uint8, min, max uint8) (byte, error) {
		if value == nil {
			return 255, nil
		}
		if *value < min || *value > max {
			return 0, fmt.Errorf("BACnet date %s must be %d..%d or wildcard", name, min, max)
		}
		return *value, nil
	}
	month, err := component("month", date.Month, 1, 12)
	if err != nil {
		return nil, err
	}
	day, err := component("day", date.Day, 1, 31)
	if err != nil {
		return nil, err
	}
	weekday, err := component("weekday", date.Weekday, 1, 7)
	if err != nil {
		return nil, err
	}
	return []byte{byte(year), month, day, weekday}, nil
}

func decodeBACnetDate(raw []byte) (BACnetCalendarDate, error) {
	if len(raw) != 4 {
		return BACnetCalendarDate{}, fmt.Errorf("BACnet date has %d bytes, want 4", len(raw))
	}
	date := BACnetCalendarDate{}
	if raw[0] != 255 {
		v := uint16(raw[0]) + 1900
		date.Year = &v
	}
	if raw[1] != 255 {
		if raw[1] < 1 || raw[1] > 12 {
			return date, errors.New("invalid BACnet date month")
		}
		v := raw[1]
		date.Month = &v
	}
	if raw[2] != 255 {
		if raw[2] < 1 || raw[2] > 31 {
			return date, errors.New("invalid BACnet date day")
		}
		v := raw[2]
		date.Day = &v
	}
	if raw[3] != 255 {
		if raw[3] < 1 || raw[3] > 7 {
			return date, errors.New("invalid BACnet date weekday")
		}
		v := raw[3]
		date.Weekday = &v
	}
	return date, nil
}

func encodeBACnetCalendarEntry(entry BACnetCalendarEntry) ([]byte, error) {
	switch entry.Type {
	case "date":
		if entry.Date == nil || entry.Start != nil || entry.End != nil || entry.WeekNDay != nil {
			return nil, errors.New("date calendar entry requires only date")
		}
		raw, err := encodeBACnetDate(*entry.Date)
		if err != nil {
			return nil, err
		}
		return bacencoding.EncodeContextPrimitive(0, raw), nil
	case "dateRange":
		if entry.Start == nil || entry.End == nil || entry.Date != nil || entry.WeekNDay != nil {
			return nil, errors.New("dateRange calendar entry requires only start and end")
		}
		start, err := encodeBACnetDate(*entry.Start)
		if err != nil {
			return nil, err
		}
		end, err := encodeBACnetDate(*entry.End)
		if err != nil {
			return nil, err
		}
		out := bacencoding.EncodeOpeningTag(1)
		out = append(out, bacencoding.EncodeApplicationPrimitive(uint8(bacencoding.AppTagDate), start)...)
		out = append(out, bacencoding.EncodeApplicationPrimitive(uint8(bacencoding.AppTagDate), end)...)
		return append(out, bacencoding.EncodeClosingTag(1)...), nil
	case "weekNDay":
		if entry.WeekNDay == nil || entry.Date != nil || entry.Start != nil || entry.End != nil {
			return nil, errors.New("weekNDay calendar entry requires only weekNDay")
		}
		part := func(name string, p *uint8, max uint8) (byte, error) {
			if p == nil {
				return 255, nil
			}
			if *p < 1 || *p > max {
				return 0, fmt.Errorf("weekNDay %s must be 1..%d or wildcard", name, max)
			}
			return *p, nil
		}
		month, err := part("month", entry.WeekNDay.Month, 14)
		if err != nil {
			return nil, err
		}
		week, err := part("week", entry.WeekNDay.Week, 6)
		if err != nil {
			return nil, err
		}
		weekday, err := part("weekday", entry.WeekNDay.Weekday, 7)
		if err != nil {
			return nil, err
		}
		return bacencoding.EncodeContextPrimitive(2, []byte{month, week, weekday}), nil
	default:
		return nil, fmt.Errorf("unsupported calendar entry type %q", entry.Type)
	}
}

func encodeBACnetCalendarEntries(entries []BACnetCalendarEntry) ([]byte, error) {
	if len(entries) > maxBACnetCalendarEntries {
		return nil, fmt.Errorf("calendar has %d entries, maximum is %d", len(entries), maxBACnetCalendarEntries)
	}
	var out []byte
	for i, e := range entries {
		raw, err := encodeBACnetCalendarEntry(e)
		if err != nil {
			return nil, fmt.Errorf("calendar entry %d: %w", i, err)
		}
		out = append(out, raw...)
		if len(out) > bacencoding.MaxAppRawLength {
			return nil, fmt.Errorf("calendar wire value exceeds %d bytes", bacencoding.MaxAppRawLength)
		}
	}
	return out, nil
}

func decodeBACnetCalendarEntry(raw []byte, offset int) (BACnetCalendarEntry, int, error) {
	if offset >= len(raw) {
		return BACnetCalendarEntry{}, offset, errors.New("missing calendar entry")
	}
	tag, h, n, err := bacencoding.ParseTag(raw[offset:])
	if err != nil {
		return BACnetCalendarEntry{}, offset, err
	}
	switch tag.TagNumber {
	case 0:
		if !tag.ContextSpecific || tag.Opening || tag.Closing || n != 4 {
			return BACnetCalendarEntry{}, offset, errors.New("invalid calendar date tag")
		}
		date, err := decodeBACnetDate(raw[offset+h : offset+h+n])
		return BACnetCalendarEntry{Type: "date", Date: &date}, offset + h + n, err
	case 1:
		if !tag.Opening {
			return BACnetCalendarEntry{}, offset, errors.New("invalid calendar date range tag")
		}
		pos := offset + h
		a, next, err := bacencoding.DecodeApplicationValue(raw, pos)
		if err != nil {
			return BACnetCalendarEntry{}, offset, err
		}
		b, next2, err := bacencoding.DecodeApplicationValue(raw, next)
		if err != nil {
			return BACnetCalendarEntry{}, offset, err
		}
		pos, err = bacencoding.ExpectClosingTag(raw, next2, 1)
		if err != nil {
			return BACnetCalendarEntry{}, offset, err
		}
		ad, ok := a.(bacencoding.AppDate)
		if !ok {
			return BACnetCalendarEntry{}, offset, errors.New("date range start is not date")
		}
		bd, ok := b.(bacencoding.AppDate)
		if !ok {
			return BACnetCalendarEntry{}, offset, errors.New("date range end is not date")
		}
		start, err := decodeBACnetDate([]byte{dateYearByte(ad.Year), ad.Month, ad.Day, ad.Weekday})
		if err != nil {
			return BACnetCalendarEntry{}, offset, err
		}
		end, err := decodeBACnetDate([]byte{dateYearByte(bd.Year), bd.Month, bd.Day, bd.Weekday})
		return BACnetCalendarEntry{Type: "dateRange", Start: &start, End: &end}, pos, err
	case 2:
		if !tag.ContextSpecific || tag.Opening || tag.Closing || n != 3 {
			return BACnetCalendarEntry{}, offset, errors.New("invalid weekNDay tag")
		}
		b := raw[offset+h : offset+h+n]
		w := BACnetWeekNDay{}
		if b[0] != 255 {
			v := b[0]
			w.Month = &v
		}
		if b[1] != 255 {
			v := b[1]
			w.Week = &v
		}
		if b[2] != 255 {
			v := b[2]
			w.Weekday = &v
		}
		if _, err := encodeBACnetCalendarEntry(BACnetCalendarEntry{Type: "weekNDay", WeekNDay: &w}); err != nil {
			return BACnetCalendarEntry{}, offset, err
		}
		return BACnetCalendarEntry{Type: "weekNDay", WeekNDay: &w}, offset + h + n, nil
	default:
		return BACnetCalendarEntry{}, offset, fmt.Errorf("unknown calendar entry tag %d", tag.TagNumber)
	}
}

func dateYearByte(year uint16) byte {
	if year == 255 {
		return 255
	}
	return byte(year - 1900)
}

func decodeBACnetCalendarEntries(raw []byte, max int) ([]BACnetCalendarEntry, error) {
	if max < 0 || max > maxBACnetCalendarEntries {
		max = maxBACnetCalendarEntries
	}
	out := make([]BACnetCalendarEntry, 0)
	for pos := 0; pos < len(raw); {
		if len(out) >= max {
			return nil, fmt.Errorf("calendar exceeds %d entries", max)
		}
		e, next, err := decodeBACnetCalendarEntry(raw, pos)
		if err != nil {
			return nil, fmt.Errorf("calendar entry %d: %w", len(out), err)
		}
		if next <= pos {
			return nil, errors.New("calendar decoder made no progress")
		}
		out = append(out, e)
		pos = next
	}
	return out, nil
}

func encodeBACnetTime(t BACnetTime) (bacencoding.AppTime, error) {
	if t.Hour > 23 || t.Minute > 59 || t.Second > 59 || t.Hundredths > 99 {
		return bacencoding.AppTime{}, errors.New("invalid schedule time")
	}
	return bacencoding.AppTime{Hour: t.Hour, Minute: t.Minute, Second: t.Second, Hundredths: t.Hundredths}, nil
}
func timeOrdinal(t BACnetTime) uint32 {
	return (((uint32(t.Hour)*60+uint32(t.Minute))*60 + uint32(t.Second)) * 100) + uint32(t.Hundredths)
}

func encodeBACnetScheduleValue(v BACnetScheduleValue) ([]byte, error) {
	if v.Type == "raw" {
		if v.Tag == nil {
			return nil, errors.New("raw schedule value requires tag")
		}
		b, err := base64.StdEncoding.DecodeString(v.RawBase64)
		if err != nil || len(b) == 0 {
			return nil, errors.New("raw schedule value requires non-empty base64")
		}
		tag, _, _, e := bacencoding.ParseTag(b)
		if e != nil || tag.ContextSpecific || tag.TagNumber != bacencoding.AppTag(*v.Tag) {
			return nil, errors.New("raw schedule value tag does not match wire value")
		}
		return b, nil
	}
	app, err := encodeBACnetValue(v.Type, v.Value)
	if err != nil {
		return nil, err
	}
	return bacencoding.EncodeApplicationValue(app)
}
func decodeBACnetScheduleValue(raw []byte, pos int) (BACnetScheduleValue, int, error) {
	tag, h, n, err := bacencoding.ParseTag(raw[pos:])
	if err != nil {
		return BACnetScheduleValue{}, pos, err
	}
	if tag.ContextSpecific {
		return BACnetScheduleValue{}, pos, errors.New("schedule value must be application tagged")
	}
	end := pos + h + n
	if tag.TagNumber > 12 {
		return BACnetScheduleValue{Type: "raw", Tag: u8ptr(uint8(tag.TagNumber)), RawBase64: base64.StdEncoding.EncodeToString(raw[pos:end])}, end, nil
	}
	app, end, err := bacencoding.DecodeApplicationValue(raw, pos)
	if err != nil {
		return BACnetScheduleValue{}, pos, err
	}
	kind, value := scheduleJSONValue(app)
	return BACnetScheduleValue{Type: kind, Value: value}, end, nil
}
func u8ptr(v uint8) *uint8 { return &v }
func scheduleJSONValue(v bacencoding.ApplicationValue) (string, any) {
	switch x := v.(type) {
	case bacencoding.AppNull:
		return "null", nil
	case bacencoding.AppBoolean:
		return "boolean", bool(x)
	case bacencoding.AppUnsignedInteger:
		return "unsigned", float64(x)
	case bacencoding.AppInteger:
		return "signed", float64(x)
	case bacencoding.AppReal:
		return "real", float64(x)
	case bacencoding.AppDouble:
		return "double", float64(x)
	case bacencoding.AppEnum:
		return "enumerated", float64(x)
	default:
		return "unsupported", bacnetApplicationJSON(v)
	}
}

func encodeBACnetDailySchedule(values []BACnetTimeValue, tag byte) ([]byte, error) {
	if len(values) > maxBACnetScheduleValues {
		return nil, fmt.Errorf("daily schedule exceeds %d values", maxBACnetScheduleValues)
	}
	out := bacencoding.EncodeOpeningTag(tag)
	var previous uint32
	for i, item := range values {
		tm, err := encodeBACnetTime(item.Time)
		if err != nil {
			return nil, fmt.Errorf("time value %d: %w", i, err)
		}
		ord := timeOrdinal(item.Time)
		if i > 0 && ord <= previous {
			return nil, errors.New("daily schedule times must be strictly increasing")
		}
		previous = ord
		tb, _ := bacencoding.EncodeApplicationValue(tm)
		vb, err := encodeBACnetScheduleValue(item.Value)
		if err != nil {
			return nil, fmt.Errorf("time value %d: %w", i, err)
		}
		out = append(out, tb...)
		out = append(out, vb...)
	}
	return append(out, bacencoding.EncodeClosingTag(tag)...), nil
}
func decodeBACnetDailySchedule(raw []byte, pos int, tag bacencoding.AppTag) ([]BACnetTimeValue, int, error) {
	next, err := bacencoding.ExpectOpeningTag(raw, pos, tag)
	if err != nil {
		return nil, pos, err
	}
	out := []BACnetTimeValue{}
	var previous uint32
	for {
		if next >= len(raw) {
			return nil, pos, errors.New("unterminated daily schedule")
		}
		t, _, _, e := bacencoding.ParseTag(raw[next:])
		if e != nil {
			return nil, pos, e
		}
		if t.Closing {
			end, e := bacencoding.ExpectClosingTag(raw, next, tag)
			return out, end, e
		}
		if len(out) >= maxBACnetScheduleValues {
			return nil, pos, errors.New("daily schedule value limit exceeded")
		}
		app, after, e := bacencoding.DecodeApplicationValue(raw, next)
		if e != nil {
			return nil, pos, e
		}
		tm, ok := app.(bacencoding.AppTime)
		if !ok {
			return nil, pos, errors.New("daily schedule entry does not start with time")
		}
		nt := BACnetTime{Hour: tm.Hour, Minute: tm.Minute, Second: tm.Second, Hundredths: tm.Hundredths}
		ord := timeOrdinal(nt)
		if len(out) > 0 && ord <= previous {
			return nil, pos, errors.New("daily schedule times are not strictly increasing")
		}
		previous = ord
		value, end, e := decodeBACnetScheduleValue(raw, after)
		if e != nil {
			return nil, pos, e
		}
		out = append(out, BACnetTimeValue{Time: nt, Value: value})
		next = end
	}
}

func encodeBACnetWeeklySchedule(days [][]BACnetTimeValue) ([]byte, error) {
	if len(days) != 7 {
		return nil, errors.New("weekly schedule must contain exactly seven days")
	}
	var out []byte
	for i, day := range days {
		raw, err := encodeBACnetDailySchedule(day, 0)
		if err != nil {
			return nil, fmt.Errorf("day %d: %w", i+1, err)
		}
		out = append(out, raw...)
		if len(out) > bacencoding.MaxAppRawLength {
			return nil, fmt.Errorf("weekly schedule wire value exceeds %d bytes", bacencoding.MaxAppRawLength)
		}
	}
	return out, nil
}
func decodeBACnetWeeklySchedule(raw []byte) ([][]BACnetTimeValue, error) {
	days := make([][]BACnetTimeValue, 7)
	pos := 0
	for i := range days {
		day, next, err := decodeBACnetDailySchedule(raw, pos, 0)
		if err != nil {
			return nil, fmt.Errorf("day %d: %w", i+1, err)
		}
		days[i] = day
		pos = next
	}
	if pos != len(raw) {
		return nil, errors.New("weekly schedule has trailing data")
	}
	return days, nil
}

func encodeBACnetSpecialEvents(events []BACnetSpecialEvent) ([]byte, error) {
	var out []byte
	for i, e := range events {
		if (e.CalendarEntry == nil) == (e.CalendarReference == "") {
			return nil, fmt.Errorf("special event %d requires exactly one period", i)
		}
		if len(e.Values) == 0 {
			return nil, fmt.Errorf("special event %d requires values", i)
		}
		if e.Priority < 1 || e.Priority > 16 {
			return nil, fmt.Errorf("special event %d priority must be 1..16", i)
		}
		if e.CalendarEntry != nil {
			ce, err := encodeBACnetCalendarEntry(*e.CalendarEntry)
			if err != nil {
				return nil, err
			}
			out = append(out, bacencoding.EncodeOpeningTag(0)...)
			out = append(out, ce...)
			out = append(out, bacencoding.EncodeClosingTag(0)...)
		} else {
			obj, err := bacclient.ParseObject(e.CalendarReference)
			if err != nil || obj.Type != 6 {
				return nil, fmt.Errorf("special event %d calendar reference is invalid", i)
			}
			out = append(out, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeObjectIdentifierValue(obj.OID()))...)
		}
		daily, err := encodeBACnetDailySchedule(e.Values, 2)
		if err != nil {
			return nil, err
		}
		out = append(out, daily...)
		out = append(out, bacencoding.EncodeContextPrimitive(3, bacencoding.EncodeUnsigned(uint32(e.Priority)))...)
		if len(out) > bacencoding.MaxAppRawLength {
			return nil, fmt.Errorf("exception schedule wire value exceeds %d bytes", bacencoding.MaxAppRawLength)
		}
	}
	return out, nil
}
func decodeBACnetSpecialEvents(raw []byte, max int) ([]BACnetSpecialEvent, error) {
	out := []BACnetSpecialEvent{}
	for pos := 0; pos < len(raw); {
		if len(out) >= max {
			return nil, errors.New("exception schedule limit exceeded")
		}
		e := BACnetSpecialEvent{}
		tag, h, n, err := bacencoding.ParseTag(raw[pos:])
		if err != nil {
			return nil, err
		}
		if tag.Opening && tag.TagNumber == 0 {
			inner := pos + h
			ce, next, err := decodeBACnetCalendarEntry(raw, inner)
			if err != nil {
				return nil, err
			}
			end, err := bacencoding.ExpectClosingTag(raw, next, 0)
			if err != nil {
				return nil, err
			}
			e.CalendarEntry = &ce
			pos = end
		} else if tag.ContextSpecific && !tag.Opening && !tag.Closing && tag.TagNumber == 1 && n == 4 {
			oid, err := bacencoding.DecodeObjectIdentifierValue(raw[pos+h : pos+h+n])
			if err != nil || oid.ObjectType() != 6 {
				return nil, errors.New("invalid special event calendar reference")
			}
			e.CalendarReference = fmt.Sprintf("calendar:%d", oid.Instance())
			pos += h + n
		} else {
			return nil, errors.New("invalid special event period")
		}
		e.Values, pos, err = decodeBACnetDailySchedule(raw, pos, 2)
		if err != nil {
			return nil, err
		}
		_, b, next, err := bacencoding.DecodeExpectedContextPrimitive(raw, pos, 3)
		if err != nil {
			return nil, err
		}
		priority, err := bacencoding.DecodeUnsigned(b)
		if err != nil || priority < 1 || priority > 16 {
			return nil, errors.New("invalid special event priority")
		}
		e.Priority = uint8(priority)
		pos = next
		out = append(out, e)
	}
	return out, nil
}
