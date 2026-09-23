package schedule

type BACnetTime struct {
	Hour       uint8
	Minute     uint8
	Second     uint8
	Hundredths uint8
}

type BACnetCalendarDate struct {
	Year    *uint16
	Month   *uint8
	Day     *uint8
	Weekday *uint8
}

type BACnetWeekNDay struct {
	Month   *uint8
	Week    *uint8
	Weekday *uint8
}

type BACnetCalendarEntry struct {
	Type     string
	Date     *BACnetCalendarDate
	Start    *BACnetCalendarDate
	End      *BACnetCalendarDate
	WeekNDay *BACnetWeekNDay
}

type BACnetScheduleValue struct {
	Type      string
	Value     any
	Tag       *uint8
	RawBase64 string
}

type BACnetTimeValue struct {
	Time  BACnetTime
	Value BACnetScheduleValue
}

type BACnetSpecialEvent struct {
	CalendarEntry     *BACnetCalendarEntry
	CalendarReference string
	Values            []BACnetTimeValue
	Priority          uint8
}
