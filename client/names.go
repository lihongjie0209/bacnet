package client

import (
	"strconv"

	"github.com/worldiety/bacnet/common/types"
)

// objectTypeByName maps canonical BACnet object-type names to their values.
//
// The library's types package only stringifies a subset of object types; this
// table lets callers accept the full set of common commissioning object types
// by name. Names use the canonical hyphenated ASHRAE 135 spelling.
var objectTypeByName = map[string]types.ObjectType{
	"analog-input":           types.ObjectTypeAnalogInput,
	"analog-output":          types.ObjectTypeAnalogOutput,
	"analog-value":           types.ObjectTypeAnalogValue,
	"binary-input":           types.ObjectTypeBinaryInput,
	"binary-output":          types.ObjectTypeBinaryOutput,
	"binary-value":           types.ObjectTypeBinaryValue,
	"calendar":               6,
	"command":                7,
	"device":                 types.ObjectTypeDevice,
	"event-enrollment":       9,
	"file":                   types.ObjectTypeFile,
	"group":                  11,
	"loop":                   types.ObjectTypeLoop,
	"multi-state-input":      types.ObjectTypeMultiStateInput,
	"multi-state-output":     types.ObjectTypeMultiStateOutput,
	"notification-class":     types.ObjectTypeNotificationClass,
	"program":                16,
	"schedule":               17,
	"averaging":              18,
	"multi-state-value":      19,
	"trend-log":              20,
	"life-safety-point":      21,
	"life-safety-zone":       22,
	"accumulator":            23,
	"pulse-converter":        24,
	"event-log":              25,
	"trend-log-multiple":     27,
	"load-control":           28,
	"structured-view":        29,
	"access-door":            30,
	"positive-integer-value": 48,
	"characterstring-value":  40,
	"datetime-value":         44,
	"integer-value":          45,
	"large-analog-value":     46,
	"octetstring-value":      47,
	"date-value":             42,
	"time-value":             50,
	"date-pattern-value":     41,
	"datetime-pattern-value": 43,
	"time-pattern-value":     49,
	"bitstring-value":        39,
	"network-port":           56,
}

// objectTypeNameByValue is the reverse of objectTypeByName, built once at init.
var objectTypeNameByValue = func() map[types.ObjectType]string {
	m := make(map[types.ObjectType]string, len(objectTypeByName))
	for name, ot := range objectTypeByName {
		// First name wins for a given value; each value here has a single
		// canonical name, so map-iteration order does not matter.
		if _, exists := m[ot]; !exists {
			m[ot] = name
		}
	}
	return m
}()

// ObjectTypeName returns a human name for an object type, falling back to the
// library's own String() (which itself falls back to "object-type(N)").
func ObjectTypeName(ot types.ObjectType) string {
	if n, ok := objectTypeNameByValue[ot]; ok {
		return n
	}
	return ot.String()
}

// ObjectTypeByName resolves a canonical object-type name to its value.
func ObjectTypeByName(name string) (types.ObjectType, bool) {
	ot, ok := objectTypeByName[name]
	return ot, ok
}

// propertyByName maps canonical BACnet property names to their identifiers.
//
// This covers the properties most relevant to discovery and commissioning. Any
// property not listed can still be referenced numerically.
var propertyByName = map[string]types.PropertyIdentifier{
	"acked-transitions":               types.PropertyIdentifierAckedTransitions,
	"application-software-version":    types.PropertyIdentifierApplicationSoftwareVersion,
	"description":                     types.PropertyIdentifierDescription,
	"object-identifier":               types.PropertyIdentifierObjectIdentifier,
	"object-name":                     types.PropertyIdentifierObjectName,
	"object-type":                     types.PropertyIdentifierObjectType,
	"present-value":                   types.PropertyIdentifierPresentValue,
	"protocol-object-types-supported": types.PropertyIdentifierProtocolObjectTypesSupported,
	"protocol-services-supported":     types.PropertyIdentifierProtocolServicesSupported,
	"protocol-version":                types.PropertyIdentifierProtocolVersion,
	"protocol-revision":               types.PropertyIdentifierProtocolRevision,
	"status-flags":                    types.PropertyIdentifierStatusFlags,
	"units":                           types.PropertyIdentifierUnits,
	"vendor-name":                     types.PropertyIdentifierVendorName,

	// Additional commonly-used properties (numeric values per ASHRAE 135 /
	// bacnet-stack bacenum.h).
	"object-list":              76,
	"system-status":            112,
	"vendor-identifier":        120,
	"model-name":               70,
	"firmware-revision":        44,
	"location":                 58,
	"max-present-value":        65,
	"min-present-value":        69,
	"out-of-service":           81,
	"reliability":              103,
	"priority-array":           87,
	"relinquish-default":       104,
	"event-state":              36,
	"polarity":                 84,
	"inactive-text":            46,
	"active-text":              4,
	"number-of-states":         74,
	"state-text":               110,
	"cov-increment":            22,
	"time-delay":               113,
	"notification-class":       17,
	"event-enable":             35,
	"high-limit":               45,
	"limit-enable":             52,
	"low-limit":                59,
	"notify-type":              72,
	"deadband":                 25,
	"resolution":               106,
	"device-address-binding":   30,
	"max-apdu-length-accepted": 62,
	"segmentation-supported":   107,
	"apdu-timeout":             11,
	"number-of-apdu-retries":   73,
	"local-date":               56,
	"local-time":               57,
	"utc-offset":               119,
	"daylight-savings-status":  24,
	"database-revision":        155,
	"profile-name":             168,
	"structured-object-list":   210,
	"subordinate-list":         211,
	"subordinate-annotations":  212,
}

// propertyNameByValue is the reverse of propertyByName, built once at init.
var propertyNameByValue = func() map[types.PropertyIdentifier]string {
	m := make(map[types.PropertyIdentifier]string, len(propertyByName))
	for name, pid := range propertyByName {
		if _, exists := m[pid]; !exists {
			m[pid] = name
		}
	}
	return m
}()

// PropertyName returns a human name for a property identifier, falling back to
// the library's String() (which yields "property-identifier(N)" for unknowns).
func PropertyName(pid types.PropertyIdentifier) string {
	if n, ok := propertyNameByValue[pid]; ok {
		return n
	}
	return pid.String()
}

// PropertyByName resolves a canonical property name to its identifier.
func PropertyByName(name string) (types.PropertyIdentifier, bool) {
	pid, ok := propertyByName[name]
	return pid, ok
}

// engineeringUnits maps common BACnet engineering-unit enumeration values to a
// short label, used when pretty-printing a units property. Only a practical
// subset is included; unknown values are printed numerically.
var engineeringUnits = map[uint32]string{
	0:   "square-meters",
	1:   "square-feet",
	2:   "milliamperes",
	3:   "amperes",
	4:   "ohms",
	5:   "volts",
	6:   "kilovolts",
	7:   "megavolts",
	8:   "volt-amperes",
	9:   "kilovolt-amperes",
	10:  "megavolt-amperes",
	11:  "volt-amperes-reactive",
	12:  "kilovolt-amperes-reactive",
	13:  "megavolt-amperes-reactive",
	14:  "degrees-phase",
	15:  "power-factor",
	16:  "joules",
	17:  "kilojoules",
	18:  "watt-hours",
	19:  "kilowatt-hours",
	20:  "btus",
	21:  "therms",
	22:  "ton-hours",
	23:  "joules-per-kilogram-dry-air",
	24:  "btus-per-pound-dry-air",
	25:  "cycles-per-hour",
	26:  "cycles-per-minute",
	27:  "hertz",
	28:  "grams-of-water-per-kilogram-dry-air",
	29:  "percent-relative-humidity",
	30:  "millimeters",
	31:  "meters",
	32:  "inches",
	33:  "feet",
	34:  "watts-per-square-foot",
	35:  "watts-per-square-meter",
	36:  "lumens",
	37:  "luxes",
	38:  "foot-candles",
	39:  "kilograms",
	40:  "pounds-mass",
	41:  "tons",
	42:  "kilograms-per-second",
	47:  "watts",
	48:  "kilowatts",
	49:  "megawatts",
	62:  "degrees-celsius",
	63:  "kelvin",
	64:  "degrees-fahrenheit",
	65:  "degree-days-celsius",
	66:  "degree-days-fahrenheit",
	84:  "cubic-feet-per-minute",
	85:  "cubic-meters-per-second",
	87:  "liters-per-second",
	88:  "liters-per-minute",
	95:  "no-units",
	96:  "parts-per-million",
	97:  "parts-per-billion",
	98:  "percent",
	119: "pounds-mass-per-second",
}

// UnitsName returns a label for an engineering-units enumeration value,
// falling back to the decimal number when unknown.
func UnitsName(v uint32) string {
	if n, ok := engineeringUnits[v]; ok {
		return n
	}
	return strconv.FormatUint(uint64(v), 10)
}
