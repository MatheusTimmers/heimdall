package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Capture struct {
	Packets <-chan gopacket.Packet
	stop    func()
}

func (c *Capture) Stop() {
	if c.stop == nil {
		return
	}
	c.stop()
}

func Start(iface string) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make(chan gopacket.Packet, 1000)
	go func() {
		defer close(packets)
		for packet := range packetSource.Packets() {
			packets <- packet
		}
	}()

	return &Capture{
		Packets: packets,
		stop:    handle.Close,
	}, nil
}
