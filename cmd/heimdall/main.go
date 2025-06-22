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
	framesTun, stopTun, err := capture.StartRawSocket("tun")
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
		ts := time.Now()
		info2, ethType, offset, err := parser.ParseEthernetFrame(raw, ts)
		info3, _, err := parser.ParseL3L4Frame(raw, ethType, offset, ts)

		if err == nil && info3.Protocol == 255 {
			out <- info2
		}
	}
	close(out)
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

	for raw := range framesTun {
		ts := time.Now()

		if len(layer2EthChan) > 0 {
			info2 := <-layer2EthChan

			info3, info4, err := parser.ParseL3L4Frame(raw, info2.EtherType, 0, ts)
			if err != nil {
				continue
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
	}
}
