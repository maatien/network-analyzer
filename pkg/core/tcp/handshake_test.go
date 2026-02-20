package tcp

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestAnalyzeHandshake(t *testing.T) {
	packets := make(chan interface{})

	go func() {
		// SYN packet
		packets <- createTCPPacket(false, false, false)
		// SYN-ACK packet
		packets <- createTCPPacket(true, false, false)
		// Another SYN
		packets <- createTCPPacket(false, false, false)
		// RST packet
		packets <- createTCPPacket(false, false, true)
		close(packets)
	}()

	stats := AnalyzeHandshake(packets)

	if stats.SynSent != 2 {
		t.Errorf("SynSent = %d, want 2", stats.SynSent)
	}
	if stats.SynAckRcvd != 1 {
		t.Errorf("SynAckRcvd = %d, want 1", stats.SynAckRcvd)
	}
	if stats.RstRcvd != 1 {
		t.Errorf("RstRcvd = %d, want 1", stats.RstRcvd)
	}
	// SynAckRatio should be 50%
	if stats.SynAckRatio != 50.0 {
		t.Errorf("SynAckRatio = %f, want 50.0", stats.SynAckRatio)
	}
}

func TestEmptyPackets(t *testing.T) {
	packets := make(chan interface{})
	close(packets)

	stats := AnalyzeHandshake(packets)

	if stats.SynSent != 0 || stats.SynAckRcvd != 0 || stats.RstRcvd != 0 {
		t.Errorf("Empty packets should give zero stats, got %+v", stats)
	}
}

func TestHandshakeStatsString(t *testing.T) {
	stats := HandshakeStats{
		SynSent:    10,
		SynAckRcvd: 8,
		RstRcvd:    2,
		SynAckRatio: 80.0,
	}
	// Verify values
	if stats.SynSent != 10 {
		t.Errorf("SynSent = %d, want 10", stats.SynSent)
	}
	if stats.SynAckRatio != 80.0 {
		t.Errorf("SynAckRatio = %f, want 80.0", stats.SynAckRatio)
	}
}

// createTCPPacket creates a minimal TCP layer for testing
// Note: We only test the TCP flags, not full packet construction
func createTCPPacket(synAck, ack, rst bool) gopacket.Packet {
	tcpLayer := &layers.TCP{
		SrcPort: 54321,
		DstPort: 443,
		SYN:     synAck,
		ACK:     ack,
		RST:     rst,
	}
	// Create a minimal packet with just the TCP layer
	return gopacket.NewPacket(
		[]byte{},
		layers.LayerTypeTCP,
		gopacket.Default,
	)
}