// Package conntrack reads and parses Linux conntrack data
package conntrack

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Entry represents a single conntrack entry
type Entry struct {
	Proto      string
	State      string
	SrcIP      string
	DstIP      string
	SrcPort    string
	DstPort    string
	Timeout    int
	IPBytesIn  uint64
	IPBytesOut uint64
	PacketsIn  uint64
	PacketsOut uint64
}

// Counters holds aggregated connection statistics
type Counters struct {
	Total      int
	Established int
	SynSent    int
	Unreplied  int
	Other      int
}

// ReadConntrack parses /proc/net/nf_conntrack and returns entries
func ReadConntrack() ([]Entry, error) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/nf_conntrack: %w", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry, err := parseLine(scanner.Text())
		if err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// CountStates aggregates entries by state
func CountStates(entries []Entry) Counters {
	var c Counters
	for _, e := range entries {
		switch e.State {
		case "ESTABLISHED":
			c.Established++
		case "SYN_SENT":
			c.SynSent++
		case "UNREPLIED":
			c.Unreplied++
		default:
			c.Other++
		}
		c.Total++
	}
	return c
}

func parseLine(line string) (Entry, error) {
	e := Entry{}
	fields := strings.Fields(line)

	// conntrack line format: family l3proto l4proto l4num timeout state [key=value]...
	// Skip first 6 fields (family, l3proto, l4proto, l4num, timeout, state)
	// Then parse key=value pairs
	for i := 6; i < len(fields); i++ {
		field := fields[i]
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "src":
			e.SrcIP = kv[1]
		case "dst":
			e.DstIP = kv[1]
		case "sport":
			e.SrcPort = kv[1]
		case "dport":
			e.DstPort = kv[1]
		case "tcp_state":
			e.State = kv[1]
		case "timeout":
			fmt.Sscanf(kv[1], "%d", &e.Timeout)
		}
	}

	// Determine protocol from field 2 (index 2)
	if len(fields) > 2 {
		e.Proto = fields[2]
	}

	// Determine state from field 5 (index 5) if not set from tcp_state
	if e.State == "" && len(fields) > 5 {
		e.State = fields[5]
	}

	// infer state from timeout or mark if missing
	if e.State == "" {
		if e.Timeout > 0 {
			e.State = "UNREPLIED" // fallback heuristic
		}
	}
	return e, nil
}