package client

import (
	"net/netip"
	"testing"
	"time"
)

func TestValidateForeignDeviceConfig(t *testing.T) {
	resolved, err := validateForeignDeviceConfig(&ForeignDeviceConfig{
		BBMD: netip.MustParseAddrPort("192.0.2.10:47808"), TTL: 60 * time.Second, RenewBefore: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ttl != 60 || resolved.renewEvery != 50*time.Second {
		t.Fatalf("resolved=%#v", resolved)
	}
	for _, config := range []*ForeignDeviceConfig{
		{},
		{BBMD: netip.MustParseAddrPort("[::1]:47808"), TTL: time.Minute, RenewBefore: 10 * time.Second},
		{BBMD: netip.MustParseAddrPort("192.0.2.10:47808"), TTL: 500 * time.Millisecond, RenewBefore: 100 * time.Millisecond},
		{BBMD: netip.MustParseAddrPort("192.0.2.10:47808"), TTL: time.Minute, RenewBefore: time.Minute},
	} {
		if _, err = validateForeignDeviceConfig(config); err == nil {
			t.Fatalf("accepted %#v", config)
		}
	}
}
