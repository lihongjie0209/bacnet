// Package schedule encodes and decodes BACnet Calendar, Weekly_Schedule, and
// Exception_Schedule property values while preserving BACnet wildcards and
// application-tag identity.
package schedule

import "errors"

// EncodeCalendarEntries encodes a BACnet Calendar property's ordered entries.
func EncodeCalendarEntries(entries []BACnetCalendarEntry) ([]byte, error) {
	return encodeBACnetCalendarEntries(entries)
}

// DecodeCalendarEntries decodes a BACnet Calendar property with a caller-owned
// entry bound.
func DecodeCalendarEntries(raw []byte, maxEntries int) ([]BACnetCalendarEntry, error) {
	return decodeBACnetCalendarEntries(raw, maxEntries)
}

// EncodeWeeklySchedule encodes the seven ordered days of a BACnet
// Weekly_Schedule property.
func EncodeWeeklySchedule(days [][]BACnetTimeValue) ([]byte, error) {
	return encodeBACnetWeeklySchedule(days)
}

// DecodeWeeklySchedule decodes the seven ordered days of a BACnet
// Weekly_Schedule property.
func DecodeWeeklySchedule(raw []byte) ([][]BACnetTimeValue, error) {
	return decodeBACnetWeeklySchedule(raw)
}

// EncodeSpecialEvents encodes a BACnet Exception_Schedule property.
func EncodeSpecialEvents(events []BACnetSpecialEvent) ([]byte, error) {
	return encodeBACnetSpecialEvents(events)
}

// DecodeSpecialEvents decodes a BACnet Exception_Schedule property with a
// caller-owned event bound.
func DecodeSpecialEvents(raw []byte, maxEvents int) ([]BACnetSpecialEvent, error) {
	return decodeBACnetSpecialEvents(raw, maxEvents)
}

// EncodeEffectivePeriod encodes the two BACnet Date values of a Schedule
// object's Effective_Period property.
func EncodeEffectivePeriod(period BACnetEffectivePeriod) ([]byte, error) {
	return encodeBACnetEffectivePeriod(period)
}

// DecodeEffectivePeriod decodes a complete Schedule Effective_Period value.
func DecodeEffectivePeriod(raw []byte) (BACnetEffectivePeriod, error) {
	return decodeBACnetEffectivePeriod(raw)
}

// EncodeValue encodes one application-tagged Schedule value.
func EncodeValue(value BACnetScheduleValue) ([]byte, error) {
	return encodeBACnetScheduleValue(value)
}

// DecodeValue decodes one complete application-tagged Schedule value.
func DecodeValue(raw []byte) (BACnetScheduleValue, error) {
	value, end, err := decodeBACnetScheduleValue(raw, 0)
	if err != nil {
		return BACnetScheduleValue{}, err
	}
	if end != len(raw) {
		return BACnetScheduleValue{}, errors.New("BACnet schedule value has trailing data")
	}
	return value, nil
}
