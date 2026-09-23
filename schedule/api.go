// Package schedule encodes and decodes BACnet Calendar, Weekly_Schedule, and
// Exception_Schedule property values while preserving BACnet wildcards and
// application-tag identity.
package schedule

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
