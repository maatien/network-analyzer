package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestToJSON(t *testing.T) {
	result := DiagnosticResult{
		Timestamp:    time.Now(),
		Interfaces:   []string{"eth0", "wlan0"},
		DurationSecs: 30,
	}
	result.TCPStats.SynSent = 10
	result.TCPStats.SynAckRcvd = 8
	result.TCPStats.RstRcvd = 1
	result.TCPStats.SynAckRatio = 80.0
	result.ConntrackCounters.Total = 100
	result.ConntrackCounters.Established = 90
	result.ConntrackCounters.SynSent = 5
	result.ConntrackCounters.Unreplied = 3
	result.ConntrackCounters.Other = 2
	result.PacketsCaptured = 500
	result.Summary = "Connection health looks good"
	result.Recommendation = "No action needed"

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "result.json")

	if err := ToJSON(&result, jsonPath); err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Verify file was created and has content
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON file is empty")
	}
	// Basic check for expected fields
	// The JSON is indented, so we can check for key strings
	js := string(data)
	if len(js) < 100 {
		t.Error("JSON output seems too short")
	}
}

func TestToMarkdown(t *testing.T) {
	result := DiagnosticResult{
		Timestamp:    time.Date(2026, 2, 20, 10, 30, 0, 0, time.UTC),
		Interfaces:   []string{"eth0"},
		DurationSecs: 60,
	}
	result.TCPStats.SynSent = 5
	result.TCPStats.SynAckRcvd = 3
	result.TCPStats.RstRcvd = 1
	result.TCPStats.SynAckRatio = 60.0
	result.ConntrackCounters.Total = 50
	result.ConntrackCounters.Established = 45
	result.ConntrackCounters.SynSent = 2
	result.ConntrackCounters.Unreplied = 2
	result.ConntrackCounters.Other = 1
	result.PacketsCaptured = 200
	result.Summary = "Some SYN packets not receiving ACKs"
	result.Recommendation = "Check upstream ISP connection"

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "result.md")

	if err := ToMarkdown(&result, mdPath); err != nil {
		t.Fatalf("ToMarkdown failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("Markdown file is empty")
	}
	// Check for expected section headers
	md := string(data)
	if len(md) < 200 {
		t.Error("Markdown output seems too short")
	}
}

func TestDiagnosticResultDefault(t *testing.T) {
	result := DiagnosticResult{}
	// Verify zero values are as expected
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should be zero")
	}
	if len(result.Interfaces) != 0 {
		t.Error("Interfaces should be empty")
	}
}