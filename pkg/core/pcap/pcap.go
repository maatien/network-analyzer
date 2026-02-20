// Package pcap provides packet capture utilities using gopacket
package pcap

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// CaptureHandle wraps a pcap handle
type CaptureHandle struct {
	handle          *pcap.Handle
	iface           string
	packetsCaptured int64 // atomic counter
}

// NewCapture opens a packet capture on the given interface
func NewCapture(iface string, filter string, timeout time.Duration) (*CaptureHandle, error) {
	handle, err := pcap.OpenLive(iface, int32(65536), false, timeout)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive(%s): %w", iface, err)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("SetBPFFilter(%s): %w", filter, err)
		}
	}
	return &CaptureHandle{handle: handle, iface: iface}, nil
}

// Close releases the capture handle
func (c *CaptureHandle) Close() {
	c.handle.Close()
}

// Capture reads packets and sends them to the provided channel (as interface{})
func (c *CaptureHandle) Capture(ch chan<- interface{}) error {
	for {
		data, _, err := c.handle.ReadPacketData()
		if err != nil {
			break
		}
		if data == nil {
			break
		}
		packet := gopacket.NewPacket(data, c.handle.LinkType(), gopacket.DecodeOptions{
			SkipDecodeRecovery: true,
		})
		ch <- packet
		atomic.AddInt64(&c.packetsCaptured, 1)
	}
	return nil
}

// PacketsCaptured returns the number of packets captured so far
func (c *CaptureHandle) PacketsCaptured() int {
	return int(atomic.LoadInt64(&c.packetsCaptured))
}

// Packets returns a channel of decoded packets (alternative interface)
func (c *CaptureHandle) Packets() <-chan gopacket.Packet {
	ch := make(chan gopacket.Packet)
	go func() {
		defer close(ch)
		for {
			data, _, err := c.handle.ReadPacketData()
			if err != nil {
				break
			}
			if data == nil {
				break
			}
			packet := gopacket.NewPacket(data, c.handle.LinkType(), gopacket.DecodeOptions{
				SkipDecodeRecovery: true,
			})
			ch <- packet
			atomic.AddInt64(&c.packetsCaptured, 1)
		}
	}()
	return ch
}

// Interface describes a network interface
type Interface struct {
	Name        string
	Description string
	Addresses   []string
}

// Interfaces returns a list of available network interfaces
func Interfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	result := make([]Interface, len(devs))
	for i, d := range devs {
		addrs := make([]string, len(d.Addresses))
		for j, a := range d.Addresses {
			addrs[j] = a.IP.String()
		}
		result[i] = Interface{
			Name:        d.Name,
			Description: d.Description,
			Addresses:   addrs,
		}
	}
	return result, nil
}