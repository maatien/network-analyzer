// Package main provides the network-app CLI.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"network-app/pkg/core/conntrack"
	"network-app/pkg/core/pcap"
	"network-app/pkg/core/report"
	"network-app/pkg/core/tcp"
)

var (
	// version info – set by Go linker at build time
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "network-app",
		Short: "Network diagnostics tool",
		Long: `network-app - Cross‑platform network diagnostics CLI

Provides packet capture, TCP handshake analysis, conntrack statistics,
and generates human‑readable reports (JSON/Markdown).`,
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
	}

	rootCmd.AddCommand(diagnoseCmd, interfacesCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// diagnose command
// -----------------------------------------------------------------------------

var diagnoseFlags = struct {
	interfaceName string
	duration      int
	output        string
	format        string
	filter        string
}{
	duration: 30,
	format:   "markdown",
}

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Run diagnostics on a network interface",
	Long: `Capture packets, analyse TCP handshakes, read conntrack data,
and generate a diagnostic report (JSON or Markdown).

Example:
  network-app diagnose -i eth0 -d 60 -f json -o result.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if diagnoseFlags.interfaceName == "" {
			return fmt.Errorf("required flag --interface/-i not set")
		}
		if diagnoseFlags.duration <= 0 {
			return fmt.Errorf("duration must be > 0")
		}
		if diagnoseFlags.format != "json" && diagnoseFlags.format != "markdown" {
			return fmt.Errorf("format must be 'json' or 'markdown', got %q", diagnoseFlags.format)
		}

		// Capture packets
		fmt.Printf("Capturing on %s for %d seconds...\n", diagnoseFlags.interfaceName, diagnoseFlags.duration)

		// Create capture source
		handle, err := pcap.NewCapture(diagnoseFlags.interfaceName, diagnoseFlags.filter, time.Duration(diagnoseFlags.duration)*time.Second)
		if err != nil {
			// Friendly hint for permission errors
			if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "Operation not permitted") {
				return fmt.Errorf("permission denied while opening interface %q – packet capture usually requires root privileges.\n"+
					"Try running with sudo or give the binary the required capabilities:\n"+
					"  sudo setcap cap_net_raw,cap_net_admin=eip ./bin/network-app",
					diagnoseFlags.interfaceName)
			}
			return fmt.Errorf("failed to open interface: %w", err)
		}
		defer handle.Close()

		// Packet channel for TCP analysis
		packets := make(chan interface{})

		// Run capture in background
		go func() {
			defer close(packets)
			if err := handle.Capture(packets); err != nil {
				fmt.Fprintf(os.Stderr, "Capture error: %v\n", err)
			}
		}()

		// Analyze TCP handshakes
		tcpStats := tcp.AnalyzeHandshake(packets)

		// Read conntrack
		connEntries, err := conntrack.ReadConntrack()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read conntrack: %v\n", err)
			connEntries = []conntrack.Entry{}
		}
		connStats := conntrack.CountStates(connEntries)

		// Build result
		result := report.DiagnosticResult{
			Timestamp:    time.Now(),
			DurationSecs: diagnoseFlags.duration,
			TCPStats: struct {
				SynSent     int     `json:"syn_sent"`
				SynAckRcvd  int     `json:"syn_ack_received"`
				RstRcvd     int     `json:"rst_received"`
				SynAckRatio float64 `json:"syn_ack_ratio_percent"`
			}{
				SynSent:     tcpStats.SynSent,
				SynAckRcvd:  tcpStats.SynAckRcvd,
				RstRcvd:     tcpStats.RstRcvd,
				SynAckRatio: tcpStats.SynAckRatio,
			},
			ConntrackCounters: struct {
				Total       int `json:"total"`
				Established int `json:"established"`
				SynSent     int `json:"syn_sent"`
				Unreplied   int `json:"unreplied"`
				Other       int `json:"other"`
			}{
				Total:       connStats.Total,
				Established: connStats.Established,
				SynSent:     connStats.SynSent,
				Unreplied:   connStats.Unreplied,
				Other:       connStats.Other,
			},
			PacketsCaptured: int(handle.PacketsCaptured()),
		}

		// Simple summary
		result.Summary = fmt.Sprintf("Captured %d packets, %d SYN sent, %.1f%% SYN-ACK ratio, %d conntrack entries",
			result.PacketsCaptured, result.TCPStats.SynSent, result.TCPStats.SynAckRatio, result.ConntrackCounters.Total)
		result.Recommendation = "Check SYN-ACK ratio; low values may indicate packet loss or network issues."

		// Write report
		var writeErr error
		if diagnoseFlags.format == "json" {
			writeErr = report.ToJSON(&result, diagnoseFlags.output)
		} else {
			writeErr = report.ToMarkdown(&result, diagnoseFlags.output)
		}
		if writeErr != nil {
			return fmt.Errorf("failed to write report: %w", writeErr)
		}

		fmt.Printf("Report written to %s\n", diagnoseFlags.output)
		return nil
	},
}

func init() {
	diagnoseCmd.Flags().StringVarP(&diagnoseFlags.interfaceName, "interface", "i", "", "Network interface to capture on (required)")
	diagnoseCmd.Flags().IntVarP(&diagnoseFlags.duration, "duration", "d", 30, "Capture duration in seconds")
	diagnoseCmd.Flags().StringVarP(&diagnoseFlags.output, "output", "o", "report.md", "Output file path")
	diagnoseCmd.Flags().StringVarP(&diagnoseFlags.format, "format", "f", "markdown", "Output format (json or markdown)")
	diagnoseCmd.Flags().StringVar(&diagnoseFlags.filter, "filter", "", "BPF filter (e.g., 'tcp port 80')")
}

// -----------------------------------------------------------------------------
// interfaces command
// -----------------------------------------------------------------------------

var interfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List available network interfaces",
	Long:  "Prints a list of all network interfaces that can be used for packet capture.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ifaces, err := pcap.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to list interfaces: %w", err)
		}
		for _, iface := range ifaces {
			fmt.Println(iface)
		}
		return nil
	},
}

// -----------------------------------------------------------------------------
// version command
// -----------------------------------------------------------------------------

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Prints the version, commit hash, and build date of the binary.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("network-app %s (commit %s, built %s)\n", version, commit, date)
	},
}