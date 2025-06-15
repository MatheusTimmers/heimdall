package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

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
	cap, err := capture.Start(iface)
	if err != nil {
		log.Fatalf("failed to start capture: %v", err)
	}
	defer cap.Stop()

	ps := parser.New(cap.Packets)

	var wg sync.WaitGroup
	wg.Add(3)
	go consume(ps.L2, layer2Logger.Log, &wg)
	go consume(ps.L3, layer3Logger.Log, &wg)
	go consume(ps.L4, layer4Logger.Log, &wg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
	cap.Stop()
	wg.Wait()
}

func consume[T any](in <-chan T, logFn func(T) error, wg *sync.WaitGroup) {
	defer wg.Done()
	for pkt := range in {
		if err := logFn(pkt); err != nil {
			log.Printf("error logging: %v", err)
		}
	}
}
