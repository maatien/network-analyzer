package pcap

import (
	"testing"
	"time"
)

func TestNewCapture(t *testing.T) {
	// Skip if not running as root or no interfaces available
	ifaces, err := Interfaces()
	if err != nil {
		t.Skipf("No interfaces available: %v", err)
	}
	if len(ifaces) == 0 {
		t.Skip("No network interfaces found")
	}

	iface := ifaces[0].Name
	handle, err := NewCapture(iface, "tcp", 5*time.Second)
	if err != nil {
		t.Fatalf("NewCapture(%s) failed: %v", iface, err)
	}
	defer handle.Close()

	// Verify handle is valid
	if handle.handle == nil {
		t.Error("Capture handle is nil")
	}
}

func TestCaptureStats(t *testing.T) {
	ifaces, err := Interfaces()
	if err != nil {
		t.Skipf("No interfaces available: %v", err)
	}
	if len(ifaces) == 0 {
		t.Skip("No network interfaces found")
	}

	iface := ifaces[0].Name
	handle, err := NewCapture(iface, "", 1*time.Second)
	if err != nil {
		t.Fatalf("NewCapture(%s) failed: %v", iface, err)
	}
	defer handle.Close()

	// Start capture briefly
	go func() {
		for range handle.Packets() {
			// Drain packets
		}
	}()
	time.Sleep(500 * time.Millisecond)

	stats, err := handle.Stats()
	if err != nil {
		t.Fatalf("Stats() failed: %v", err)
	}
	if stats.PacketsReceived < 0 {
		t.Errorf("Invalid packets received: %d", stats.PacketsReceived)
	}
}

func TestInterfaces(t *testing.T) {
	ifaces, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() failed: %v", err)
	}
	// At minimum we should have loopback
	if len(ifaces) == 0 {
		t.Error("No interfaces returned")
	}
}