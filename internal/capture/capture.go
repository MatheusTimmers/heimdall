package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Capture struct {
	Packets <-chan []byte
	stop    func()
}

func (c *Capture) Stop() {
	if c.stop == nil {
		return
	}
	c.stop()
	return
}

func Start(iface string) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make(chan []byte)
	go func() {
		defer close(packets)
		for packet := range packetSource.Packets() {
			packets <- packet.Data()
		}
	}()

	return &Capture{
		Packets: packets,
		stop:    handle.Close,
	}, nil
}
