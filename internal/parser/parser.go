// internal/parser/manual.go
package parser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// Layer2Info ...
type Layer2Info struct {
	Timestamp    time.Time
	SrcMAC       string
	DstMAC       string
	EtherType    uint16
	PacketLength int
}

// Layer3Info ...
type Layer3Info struct {
	Timestamp    time.Time
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     uint8
	ProtocolName string
	PacketLength int
}

// Layer4Info ...
type Layer4Info struct {
	Timestamp    time.Time
	SrcIP        net.IP
	SrcPort      uint16
	DstIP        net.IP
	DstPort      uint16
	ProtocolName string
	PacketLength int
}

func ParseEthernetFrame(data []byte, ts time.Time) (
	l2 Layer2Info,
	ethType uint16,
	offset int,
	err error,
) {
	l2, ethType, offset, err = parseEthernet(data, ts)
	return
}

func ParseL3L4Frame(data []byte, ethType uint16, offset int, ts time.Time) (
	l3 Layer3Info,
	l4 Layer4Info,
	err error,
) {
	var newOffset int
	if l3, newOffset, err = parseL3(data, ethType, offset, ts); err != nil {
		return
	}
	if l4, err = parseL4(data, newOffset, l3, ts); err != nil {
		return
	}
	return
}

func parseEthernet(data []byte, ts time.Time) (
	l2 Layer2Info, ethType uint16, offset int, err error,
) {
	totalLen := len(data)
	if totalLen < 14 {
		err = errors.New("frame muito curto")
		return
	}
	l2.Timestamp = ts
	l2.PacketLength = totalLen
	l2.DstMAC = net.HardwareAddr(data[0:6]).String()
	l2.SrcMAC = net.HardwareAddr(data[6:12]).String()

	ethType = binary.BigEndian.Uint16(data[12:14])
	offset = 14

	for ethType == 0x8100 && totalLen >= offset+4 {
		ethType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}
	l2.EtherType = ethType
	return
}

func parseL3(
	data []byte,
	ethType uint16,
	offset int,
	ts time.Time,
) (l3 Layer3Info, newOffset int, err error) {
	totalLen := len(data)
	l3.Timestamp = ts
	l3.PacketLength = totalLen
	newOffset = offset

	switch ethType {
	case 0x0806: // ARP
		if totalLen < offset+28 {
			err = errors.New("ARP truncado")
			return
		}
		l3.SrcIP = net.IP(data[offset+14 : offset+18])
		l3.DstIP = net.IP(data[offset+24 : offset+28])
		l3.Protocol = 0
		l3.ProtocolName = "ARP"

	case 0x0800: // IPv4
		if totalLen < offset+20 {
			err = errors.New("IPv4 header incompleto")
			return
		}
		ihl := int(data[offset]&0x0F) * 4
		if ihl < 20 || totalLen < offset+ihl {
			err = errors.New("IPv4 IHL inválido")
			return
		}
		l3.SrcIP = net.IP(data[offset+12 : offset+16])
		l3.DstIP = net.IP(data[offset+16 : offset+20])
		proto := data[offset+9]
		l3.Protocol = proto
		l3.ProtocolName = "IPv4"

		newOffset = offset + ihl

	case 0x86DD: // IPv6
		if totalLen < offset+40 {
			err = errors.New("IPv6 header incompleto")
			return
		}
		l3.SrcIP = net.IP(data[offset+8 : offset+24])
		l3.DstIP = net.IP(data[offset+24 : offset+40])
		proto := data[offset+6]
		l3.Protocol = proto
		l3.ProtocolName = "IPv6"

		newOffset = offset + 40

	default:
	}
	return
}

func parseL4(
	data []byte,
	offset int,
	l3 Layer3Info,
	ts time.Time,
) (l4 Layer4Info, err error) {
	totalLen := len(data)
	l4.Timestamp = ts
	l4.PacketLength = totalLen
	l4.SrcIP = l3.SrcIP
	l4.DstIP = l3.DstIP

	switch l3.Protocol {
	case 6: // TCP
		if totalLen < offset+4 {
			err = errors.New("TCP header incompleto")
			return
		}
		l4.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
		l4.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		l4.ProtocolName = "TCP"

	case 17: // UDP
		if totalLen < offset+4 {
			err = errors.New("UDP header incompleto")
			return
		}
		l4.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
		l4.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		l4.ProtocolName = "UDP"

	case 1:
		l4.ProtocolName = "ICMPv4"
	case 58:
		l4.ProtocolName = "ICMPv6"
	default:
		l4.ProtocolName = fmt.Sprintf("%d", l3.Protocol)
	}
	return
}
