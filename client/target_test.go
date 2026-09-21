package client

import (
	"net/netip"
	"testing"

	"github.com/worldiety/bacnet/common/types"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in       string
		wantID   bool
		wantInst uint32
		wantAddr string
		wantErr  bool
	}{
		{in: "5123", wantID: true, wantInst: 5123},
		{in: "device:5123", wantID: true, wantInst: 5123},
		{in: "DEVICE:5123", wantID: true, wantInst: 5123},
		{in: "#5123", wantID: true, wantInst: 5123},
		{in: "10.6.6.123", wantAddr: "10.6.6.123:47808"},
		{in: "10.6.6.123:47809", wantAddr: "10.6.6.123:47809"},
		{in: "", wantErr: true},
		{in: "nope", wantErr: true},
		{in: "::1", wantErr: true}, // no dot -> parsed as device id -> not a number
		{in: "1.2.3.4.5", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			tgt, err := ParseTarget(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %v, want error", tt.in, tgt)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tt.in, err)
			}
			if tgt.IsID() != tt.wantID {
				t.Fatalf("IsID = %v, want %v", tgt.IsID(), tt.wantID)
			}
			if tt.wantID && tgt.Instance() != tt.wantInst {
				t.Fatalf("Instance = %d, want %d", tgt.Instance(), tt.wantInst)
			}
			if !tt.wantID {
				if got := tgt.addr.AddrPort.String(); got != tt.wantAddr {
					t.Fatalf("addr = %s, want %s", got, tt.wantAddr)
				}
			}
		})
	}
}

func TestTargetConstructors(t *testing.T) {
	if got := TargetID(42); !got.IsID() || got.Instance() != 42 {
		t.Fatalf("TargetID(42) = %+v", got)
	}
	ap := netip.MustParseAddrPort("10.0.0.1:47808")
	if got := TargetAddr(ap); got.IsID() {
		t.Fatalf("TargetAddr should not be an ID target")
	}
}

func TestParseObject(t *testing.T) {
	tests := []struct {
		in       string
		wantType types.ObjectType
		wantInst uint32
		wantErr  bool
	}{
		{in: "analog-value:270", wantType: types.ObjectTypeAnalogValue, wantInst: 270},
		{in: "device:5123", wantType: types.ObjectTypeDevice, wantInst: 5123},
		{in: "2:270", wantType: types.ObjectTypeAnalogValue, wantInst: 270},
		{in: "network-port:1", wantType: 56, wantInst: 1},
		{in: "nope", wantErr: true},
		{in: "analog-value:", wantErr: true},
		{in: "unknown-type:1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			obj, err := ParseObject(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseObject(%q) = %v, want error", tt.in, obj)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseObject(%q): %v", tt.in, err)
			}
			if obj.Type != tt.wantType || obj.Instance != tt.wantInst {
				t.Fatalf("got %+v, want type=%d inst=%d", obj, tt.wantType, tt.wantInst)
			}
		})
	}
}

func TestObjectString(t *testing.T) {
	obj := Object{Type: types.ObjectTypeAnalogInput, Instance: 250}
	if got := obj.String(); got != "analog-input:250" {
		t.Fatalf("String = %q, want analog-input:250", got)
	}
}

func TestParseProperty(t *testing.T) {
	tests := []struct {
		in   string
		want types.PropertyIdentifier
	}{
		{"present-value", types.PropertyIdentifierPresentValue},
		{"object-name", types.PropertyIdentifierObjectName},
		{"protocol-revision", 139},
		{"85", 85},
		{"object-list", 76},
		{"limit-enable", 52},
		{"event-enable", 35},
		{"notify-type", 72},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			pid, err := ParseProperty(tt.in)
			if err != nil {
				t.Fatalf("ParseProperty(%q): %v", tt.in, err)
			}
			if pid != tt.want {
				t.Fatalf("got %d, want %d", pid, tt.want)
			}
		})
	}
	if _, err := ParseProperty("bogus"); err == nil {
		t.Fatal("ParseProperty(bogus) should error")
	}
}
