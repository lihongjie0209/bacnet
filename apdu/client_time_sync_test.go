package apdu

import (
	"context"
	"testing"
	"time"

	"github.com/worldiety/bacnet/common/netprim"
)

func TestClientTimeSynchronization(t *testing.T) {
	tests := []struct {
		name    string
		utc     bool
		service ServiceChoice
	}{
		{name: "local", service: ServiceChoiceTimeSynchronization},
		{name: "utc", utc: true, service: ServiceChoiceUTCTimeSynchronization},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTestNPDUTransport()
			ase, err := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 1}, transport)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := NewClient(ase, ClientConfig{})
			if err != nil {
				t.Fatal(err)
			}
			dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{1})
			instant := time.Date(2026, time.September, 19, 14, 3, 2, 340_000_000, time.FixedZone("CST", 8*60*60))
			if err := raw.TimeSynchronization(context.Background(), dst, instant, tt.utc); err != nil {
				t.Fatalf("TimeSynchronization: %v", err)
			}
			sent := <-transport.ch
			decoded, err := decodeAPDU(sent.packet.APDUBytes())
			if err != nil {
				t.Fatal(err)
			}
			if decoded.ServiceChoice != tt.service {
				t.Fatalf("service = %v, want %v", decoded.ServiceChoice, tt.service)
			}
			want := []byte{0xa4, 126, 9, 19, 6, 0xb4, 14, 3, 2, 34}
			if string(decoded.Payload) != string(want) {
				t.Fatalf("payload = %v, want %v", decoded.Payload, want)
			}
		})
	}
}

func TestClientTimeSynchronizationRejectsUnrepresentableYear(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 1}, transport)
	raw, _ := NewClient(ase, ClientConfig{})
	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{1})
	if err := raw.TimeSynchronization(context.Background(), dst, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), false); err == nil {
		t.Fatal("expected year validation error")
	}
}
