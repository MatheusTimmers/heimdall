package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MatheusTimmers/heimdall/internal/capture"
	"github.com/MatheusTimmers/heimdall/internal/logger"
	"github.com/MatheusTimmers/heimdall/internal/parser"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <interface>", os.Args[0])
	}

	layer2Logger, err := logger.NewLayer2Logger("camada2.csv")
	if err != nil {
		log.Fatalf("failed to create layer 2 logger: %v", err)
	}
	defer layer2Logger.Close()

	layer3Logger, err := logger.NewLayer3Logger("camada3.csv")
	if err != nil {
		log.Fatalf("failed to create layer 3 logger: %v", err)
	}
	defer layer3Logger.Close()

	layer4Logger, err := logger.NewLayer4Logger("camada4.csv")
	if err != nil {
		log.Fatalf("failed to create layer 4 logger: %v", err)
	}
	defer layer4Logger.Close()

	iface := os.Args[1]
	frames, stop, err := capture.StartRawSocket(iface)
	defer stop()
	if err != nil {
		log.Fatalf("failed to start capture: %v", err)
	}

	for raw := range frames {
		ts := time.Now()

		log.Printf("Received raw: %x", raw)

		info2, info3, info4, err := parser.ParseFrame(raw, ts)
		if err != nil {
			continue
		}

		log.Printf("    [L2] %s → %s | EtherType: 0x%04x | Comprimento: %d",
			info2.SrcMAC,
			info2.DstMAC,
			info2.EtherType,
			info2.PacketLength,
		)

		log.Printf("    [L3] %s → %s | Protocolo: %s (ID=%d) | Comprimento: %d",
			info3.SrcIP,
			info3.DstIP,
			info3.ProtocolName,
			info3.Protocol,
			info3.PacketLength,
		)

		if info4.ProtocolName != "" {
			log.Printf("    [L4] %s:%d → %s:%d | Protocolo: %s | Comprimento: %d",
				info4.SrcIP,
				info4.SrcPort,
				info4.DstIP,
				info4.DstPort,
				info4.ProtocolName,
				info4.PacketLength,
			)
		}

		if err := layer2Logger.Log(info2); err != nil {
			log.Printf("erro log L2: %v", err)
		}
		if err := layer3Logger.Log(info3); err != nil {
			log.Printf("erro log L3: %v", err)
		}

		if info4.ProtocolName != "" {
			if err := layer4Logger.Log(info4); err != nil {
				log.Printf("erro log L4: %v", err)
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		stop()
		layer2Logger.Close()
		layer3Logger.Close()
		layer4Logger.Close()
		os.Exit(0)
	}()
	log.Println("Shutting down...")
}
