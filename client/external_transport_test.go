package client

import (
	"context"
	"testing"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/npdu"
)

type externalTestTransport struct{ destinations chan netprim.Address }

func (t externalTestTransport) SendNPDU(_ context.Context, destination netprim.Address, _ npdu.NetworkLayerProtocolDataUnit) error {
	if t.destinations != nil {
		t.destinations <- destination
	}
	return nil
}

func TestNewWithTransportAndTargetAddress(t *testing.T) {
	client, ase, err := NewWithTransport(Config{Timeout: time.Second, Retries: 1}, externalTestTransport{}, apdu.MaxApduLengthAccepted(480))
	if err != nil {
		t.Fatal(err)
	}
	if client == nil || ase == nil || client.apduClient() == nil {
		t.Fatal("transport client was not fully constructed")
	}
	address, err := netprim.NewAddress(42, []byte{192, 0, 2, 1, 0xba, 0xc0})
	if err != nil {
		t.Fatal(err)
	}
	target := TargetAddress(address)
	if target.IsID() || !target.addr.Equal(address) {
		t.Fatalf("target = %#v", target)
	}
	native := TargetAddress(netprim.Address{Network: netprim.LocalNetwork, MAC: []byte{7}})
	if got := native.String(); got != "local:07" {
		t.Fatalf("native target string = %q", got)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewWithTransportRejectsNilTransport(t *testing.T) {
	if _, _, err := NewWithTransport(Config{}, nil, apdu.MaxApduLengthAccepted(480)); err == nil {
		t.Fatal("expected nil transport error")
	}
}

func TestExternalTransportDiscoveryUsesConfiguredBroadcast(t *testing.T) {
	broadcast := netprim.Address{Network: netprim.LocalNetwork, MAC: []byte{255}}
	transport := externalTestTransport{destinations: make(chan netprim.Address, 1)}
	client, _, err := NewWithTransport(Config{TransportBroadcasts: []netprim.Address{broadcast}}, transport, apdu.MaxApduLengthAccepted(480))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err = client.Discover(t.Context(), WithWindow(time.Millisecond), WithLocalOnly()); err != nil {
		t.Fatal(err)
	}
	if destination := <-transport.destinations; !destination.Equal(broadcast) {
		t.Fatalf("destination = %#v", destination)
	}
}
