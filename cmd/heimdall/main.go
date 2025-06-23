package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MatheusTimmers/heimdall/internal/capture"
	"github.com/MatheusTimmers/heimdall/internal/logger"
	"github.com/MatheusTimmers/heimdall/internal/parser"
)

var (
	tunPackets, ethPackets, tunBytes, ethBytes uint64

	ethTypeCount = make(map[uint16]uint64)
	ethTypeMu    sync.Mutex

	tunProtoCount = make(map[uint8]uint64)
	tunProtoMu    sync.Mutex
)

func createLoggers() (*logger.Layer2Logger, *logger.Layer3Logger, *logger.Layer4Logger) {
	layer2Logger, err := logger.NewLayer2Logger("camada2.csv")
	if err != nil {
		log.Fatalf("failed to create layer 2 logger: %v", err)
	}

	layer3Logger, err := logger.NewLayer3Logger("camada3.csv")
	if err != nil {
		log.Fatalf("failed to create layer 3 logger: %v", err)
	}

	layer4Logger, err := logger.NewLayer4Logger("camada4.csv")
	if err != nil {
		log.Fatalf("failed to create layer 4 logger: %v", err)
	}
	return layer2Logger, layer3Logger, layer4Logger
}

func startInterfaces() (framesTun <-chan []byte, stopTun func(), framesEth <-chan []byte, stopEth func()) {
	framesTun, stopTun, err := capture.StartRawSocket("tun0")
	if err != nil {
		log.Fatalf("failed to start capture on tun: %v", err)
	}

	framesEth, stopEth, e := capture.StartRawSocket("eth0")
	if e != nil {
		log.Fatalf("failed to start capture on eth0: %v", e)
	}

	return framesTun, stopTun, framesEth, stopEth
}

func cleanup(
	layer2Logger *logger.Layer2Logger,
	layer3Logger *logger.Layer3Logger,
	layer4Logger *logger.Layer4Logger,
	stopTun func(),
	stopEth func(),
) {
	log.Println("Encerrando...")
	stopTun()
	stopEth()
	layer2Logger.Close()
	layer3Logger.Close()
	layer4Logger.Close()
	log.Println("Finalizado. Saindo.")
	os.Exit(0)
}

func processEthLayer2(framesEth <-chan []byte, out chan<- parser.Layer2Info) {
	for raw := range framesEth {
		atomic.AddUint64(&ethPackets, 1)
		atomic.AddUint64(&ethBytes, uint64(len(raw)))
		ts := time.Now()
		info2, ethType, offset, err := parser.ParseEthernetFrame(raw, ts)
		info3, _, err := parser.ParseL3L4Frame(raw, ethType, offset, ts)

		ethTypeMu.Lock()
		ethTypeCount[ethType]++
		ethTypeMu.Unlock()

		if err == nil && info3.Protocol == 255 {
			out <- info2
		}
	}
	close(out)
}

func processTunLayer(framesTun <-chan []byte, layer2EthChan <-chan parser.Layer2Info, layer2Logger *logger.Layer2Logger, layer3Logger *logger.Layer3Logger, layer4Logger *logger.Layer4Logger) {
	for raw := range framesTun {
		atomic.AddUint64(&tunPackets, 1)
		atomic.AddUint64(&tunBytes, uint64(len(raw)))
		ts := time.Now()

		if len(layer2EthChan) > 0 {
			info2 := <-layer2EthChan

			info3, info4, err := parser.ParseL3L4Frame(raw, info2.EtherType, 0, ts)
			if err != nil {
				continue
			}

			tunProtoMu.Lock()
			tunProtoCount[info3.Protocol]++
			tunProtoMu.Unlock()

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
	}
}

func printStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var lastTunPackets, lastEthPackets, lastTunBytes, lastEthBytes uint64
	for range ticker.C {
		curTunPackets := atomic.LoadUint64(&tunPackets)
		curEthPackets := atomic.LoadUint64(&ethPackets)
		curTunBytes := atomic.LoadUint64(&tunBytes)
		curEthBytes := atomic.LoadUint64(&ethBytes)

		ethTypeMu.Lock()
		log.Printf("[ETH0 EtherType count]:")
		for t, c := range ethTypeCount {
			log.Printf("  0x%04x: %d", t, c)
		}
		ethTypeMu.Unlock()

		tunProtoMu.Lock()
		log.Printf("[TUN Protocol count]:")
		for proto, c := range tunProtoCount {
			log.Printf("  %d: %d", proto, c)
		}
		tunProtoMu.Unlock()

		log.Printf("[STATS] tun: %d pkts (%d bytes) | eth0: %d pkts (%d bytes) | tun rate: %d pps, %d Bps | eth0 rate: %d pps, %d Bps",
			curTunPackets, curTunBytes, curEthPackets, curEthBytes,
			curTunPackets-lastTunPackets, curTunBytes-lastTunBytes,
			curEthPackets-lastEthPackets, curEthBytes-lastEthBytes,
		)
		lastTunPackets = curTunPackets
		lastEthPackets = curEthPackets
		lastTunBytes = curTunBytes
		lastEthBytes = curEthBytes
	}
}

func main() {
	layer2Logger, layer3Logger, layer4Logger := createLoggers()
	framesTun, stopTun, framesEth, stopEth := startInterfaces()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cleanup(layer2Logger, layer3Logger, layer4Logger, stopTun, stopEth)
	}()

	layer2EthChan := make(chan parser.Layer2Info, 1000)
	go processEthLayer2(framesEth, layer2EthChan)
	go printStats()
	processTunLayer(framesTun, layer2EthChan, layer2Logger, layer3Logger, layer4Logger)
}
