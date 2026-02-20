// Package tcp provides TCP handshake analysis
package tcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HandshakeStats holds SYN/SYN-ACK/RST counters
type HandshakeStats struct {
	SynSent     int
	SynAckRcvd  int
	RstRcvd     int
	SynAckRatio float64 // (SynAckRcvd / SynSent) * 100
}

// AnalyzeHandshake processes packets and tracks handshake state
func AnalyzeHandshake(packets <-chan interface{}) HandshakeStats {
	var stats HandshakeStats
	for raw := range packets {
		pkt, ok := raw.(gopacket.Packet)
		if !ok {
			continue
		}
		stats.process(pkt)
	}
	if stats.SynSent > 0 {
		stats.SynAckRatio = float64(stats.SynAckRcvd) / float64(stats.SynSent) * 100
	}
	return stats
}

func (s *HandshakeStats) process(pkt gopacket.Packet) {
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	switch tcp.SYN {
	case true:
		if tcp.ACK {
			s.SynAckRcvd++
		} else {
			s.SynSent++
		}
	case tcp.RST:
		s.RstRcvd++
	}
}