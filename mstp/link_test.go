package mstp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testLinkConfig() LinkConfig {
	return LinkConfig{
		Master: testMasterConfig(), ReadPollInterval: 5 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond, ReadBufferSize: 64, MaxInbound: 2,
	}
}

func TestLinkRunsMasterAndDeliversCopiedNPDUs(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	config := testLinkConfig()
	config.Master.NoTokenTimeout = time.Second
	link, err := NewLink(config, client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- link.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
	})

	sent := []byte{1, 0x20}
	if err = link.Send(context.Background(), 5, sent, false); err != nil {
		t.Fatal(err)
	}
	sent[0] = 9
	token, _ := EncodeFrame(Frame{Type: FrameToken, Destination: config.Master.LocalMAC, Source: 2})
	go func() { _, _ = peer.Write(token) }()
	written := readLinkTestFrame(t, peer)
	if written.Type != FrameDataNotExpectingReply || written.Destination != 5 || !bytes.Equal(written.Data, []byte{1, 0x20}) {
		t.Fatalf("written=%+v", written)
	}

	incomingData := []byte{1, 4}
	incoming, _ := EncodeFrame(Frame{Type: FrameDataNotExpectingReply, Destination: config.Master.LocalMAC, Source: 5, Data: incomingData})
	go func() { _, _ = peer.Write(incoming) }()
	select {
	case packet := <-link.Inbound():
		if packet.Source != 5 || !bytes.Equal(packet.Data, incomingData) {
			t.Fatalf("packet=%+v", packet)
		}
		incoming[len(incoming)-3] ^= 0xff
		if !bytes.Equal(packet.Data, incomingData) {
			t.Fatal("inbound data aliases decoder storage")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inbound packet")
	}
}

func TestLinkCancellationInterruptsReadAndClosesAPI(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	config := testLinkConfig()
	link, err := NewLink(config, client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- link.Run(ctx) }()
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
	if err = link.Send(context.Background(), 1, []byte{1}, false); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("send error=%v", err)
	}
	if _, open := <-link.Inbound(); open {
		t.Fatal("inbound channel remained open")
	}
}

func TestLinkFailsOnInboundBackpressure(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	config := testLinkConfig()
	config.MaxInbound = 1
	link, err := NewLink(config, client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- link.Run(ctx) }()
	for source := byte(4); source < 6; source++ {
		raw, _ := EncodeFrame(Frame{Type: FrameDataNotExpectingReply, Destination: config.Master.LocalMAC, Source: source, Data: []byte{source}})
		if _, err = peer.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err = <-done:
		if !errors.Is(err, ErrInboundFull) {
			t.Fatalf("run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not report inbound backpressure")
	}
}

func TestLinkConfigValidation(t *testing.T) {
	config := testLinkConfig()
	config.ReadBufferSize = 7
	if _, err := NewLink(config, nil); err == nil {
		t.Fatal("accepted invalid session and read buffer")
	}
}

func readLinkTestFrame(t *testing.T, peer net.Conn) Frame {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 8)
	if _, err := io.ReadFull(peer, header); err != nil {
		t.Fatal(err)
	}
	length := int(header[5])<<8 | int(header[6])
	raw := header
	if length > 0 {
		body := make([]byte, length+2)
		if _, err := io.ReadFull(peer, body); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, body...)
	}
	frame, _, err := DecodeFrame(raw, MaxDataLength)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}
