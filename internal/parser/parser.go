// internal/parser/parser.go
package parser

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Agrupa os campos extraídos da camada Ethernet.
type Layer2Info struct {
	Timestamp    time.Time
	SrcMAC       string
	DstMAC       string
	EtherType    layers.EthernetType
	PacketLength int
}

// Agrupa os campos extraídos da camada IP (v4 ou v6).
type Layer3Info struct {
	Timestamp    time.Time
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     uint8
	ProtocolName string
	PacketLength int
}

// Agrupa os campos extraídos da camada de transporte (TCP/UDP).
type Layer4Info struct {
	Timestamp    time.Time
	SrcIP        net.IP
	SrcPort      uint16
	DstIP        net.IP
	DstPort      uint16
	ProtocolName string
	PacketLength int
}

type Parser struct {
	L2 chan Layer2Info
	L3 chan Layer3Info
	L4 chan Layer4Info
}

func New(inPackets <-chan gopacket.Packet) *Parser {
	p := &Parser{
		L2: make(chan Layer2Info, 100),
		L3: make(chan Layer3Info, 100),
		L4: make(chan Layer4Info, 100),
	}
	go p.run(inPackets)
	return p
}

func (p *Parser) run(in <-chan gopacket.Packet) {
	defer func() {
		close(p.L2)
		close(p.L3)
		close(p.L4)
	}()

	for pkt := range in {
		meta := pkt.Metadata().CaptureInfo
		ts := meta.Timestamp
		length := meta.CaptureLength

		// — Camada 2: Ethernet —
		if ethL := pkt.Layer(layers.LayerTypeEthernet); ethL != nil {
			eth := ethL.(*layers.Ethernet)
			p.L2 <- Layer2Info{
				Timestamp:    ts,
				SrcMAC:       eth.SrcMAC.String(),
				DstMAC:       eth.DstMAC.String(),
				EtherType:    eth.EthernetType,
				PacketLength: length,
			}
		}

		// — Camada 3: IPv4 ou IPv6 —
		var srcIP, dstIP net.IP
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			ip := ip4.(*layers.IPv4)
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
			p.L3 <- Layer3Info{
				Timestamp:    ts,
				ProtocolName: "IPv4",
				SrcIP:        srcIP,
				DstIP:        dstIP,
				Protocol:     uint8(ip.Protocol),
				PacketLength: length,
			}
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ip := ip6.(*layers.IPv6)
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
			p.L3 <- Layer3Info{
				Timestamp:    ts,
				ProtocolName: "IPv4",
				SrcIP:        srcIP,
				DstIP:        dstIP,
				Protocol:     uint8(ip.NextHeader),
				PacketLength: length,
			}
		}

		// — Camada 4: TCP ou UDP —
		if tl := pkt.TransportLayer(); tl != nil {
			name := tl.LayerType().String()
			switch {
			case pkt.Layer(layers.LayerTypeTCP) != nil:
				tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
				p.L4 <- Layer4Info{
					Timestamp:    ts,
					ProtocolName: name,
					SrcIP:        srcIP,
					SrcPort:      uint16(tcp.SrcPort),
					DstIP:        dstIP,
					DstPort:      uint16(tcp.DstPort),
					PacketLength: length,
				}
			case pkt.Layer(layers.LayerTypeUDP) != nil:
				udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
				p.L4 <- Layer4Info{
					Timestamp:    ts,
					ProtocolName: name,
					SrcIP:        srcIP,
					SrcPort:      uint16(udp.SrcPort),
					DstIP:        dstIP,
					DstPort:      uint16(udp.DstPort),
					PacketLength: length,
				}
			}
		}
	}
}
