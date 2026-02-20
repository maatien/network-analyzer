package conntrack

import (
	"os"
	"testing"
)

func TestReadConntrack(t *testing.T) {
	// This test will only work on Linux with conntrack support
	// We'll skip if the file doesn't exist
	if _, err := os.Stat("/proc/net/nf_conntrack"); os.IsNotExist(err) {
		t.Skip("/proc/net/nf_conntrack not available")
	}

	_, err := ReadConntrack()
	if err != nil {
		t.Fatalf("ReadConntrack() failed: %v", err)
	}
	// entries can be empty on a quiet system, that's okay
}

func TestCountStates(t *testing.T) {
	entries := []Entry{
		{State: "ESTABLISHED"},
		{State: "ESTABLISHED"},
		{State: "SYN_SENT"},
		{State: "UNREPLIED"},
		{State: "OTHER"},
	}

	counters := CountStates(entries)

	if counters.Total != 5 {
		t.Errorf("Total = %d, want 5", counters.Total)
	}
	if counters.Established != 2 {
		t.Errorf("Established = %d, want 2", counters.Established)
	}
	if counters.SynSent != 1 {
		t.Errorf("SynSent = %d, want 1", counters.SynSent)
	}
	if counters.Unreplied != 1 {
		t.Errorf("Unreplied = %d, want 1", counters.Unreplied)
	}
	if counters.Other != 1 {
		t.Errorf("Other = %d, want 1", counters.Other)
	}
}

func TestParseLine(t *testing.T) {
	line := `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=93.184.216.34 sport=54321 dport=443 src=192.168.1.1 dst=192.168.1.10 sport=443 dport=54321 [ASSURED] mark=0 zone=0 use=2`
	entry, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine failed: %v", err)
	}

	if entry.Proto != "tcp" {
		t.Errorf("Proto = %s, want tcp", entry.Proto)
	}
	if entry.State != "ESTABLISHED" {
		t.Errorf("State = %s, want ESTABLISHED", entry.State)
	}
	if entry.SrcIP != "192.168.1.10" {
		t.Errorf("SrcIP = %s, want 192.168.1.10", entry.SrcIP)
	}
	if entry.DstIP != "93.184.216.34" {
		t.Errorf("DstIP = %s, want 93.184.216.34", entry.DstIP)
	}
}

func TestParseLineUnreplied(t *testing.T) {
	// Unreplied connection has no ASSURED flag
	line := `ipv4     2 tcp      6 30 SYN_SENT src=192.168.1.20 dst=8.8.8.8 sport=12345 dport=53 [UNREPLIED] mark=0 zone=0 use=0`
	entry, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine failed: %v", err)
	}

	if entry.Proto != "tcp" {
		t.Errorf("Proto = %s, want tcp", entry.Proto)
	}
	if entry.SrcIP != "192.168.1.20" {
		t.Errorf("SrcIP = %s, want 192.168.1.20", entry.SrcIP)
	}
}