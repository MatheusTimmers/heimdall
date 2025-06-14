package parser

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketInfo struct {
	Timestamp time.Time
	SrcMAC    string
	DstMAC    string
	EtherType layers.EthernetType
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  layers.IPProtocol
	SrcPort   uint16
	DstPort   uint16
}

func Parse(data []byte) (PacketInfo, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	info := PacketInfo{Timestamp: time.Now()}

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		info.SrcMAC = eth.SrcMAC.String()
		info.DstMAC = eth.DstMAC.String()
		info.EtherType = eth.EthernetType
	}

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4 := ip4.(*layers.IPv4)
		info.SrcIP = ipv4.SrcIP
		info.DstIP = ipv4.DstIP
		info.Protocol = ipv4.Protocol
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6 := ip6.(*layers.IPv6)
		info.SrcIP = ipv6.SrcIP
		info.DstIP = ipv6.DstIP
		info.Protocol = ipv6.NextHeader
	}

	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		info.SrcPort = uint16(t.SrcPort)
		info.DstPort = uint16(t.DstPort)
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		info.SrcPort = uint16(u.SrcPort)
		info.DstPort = uint16(u.DstPort)
	}

	return info, nil
}
