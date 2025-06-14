package main

import (
	"log"

	"github.com/MatheusTimmers/heimdall/internal/capture"
	"github.com/MatheusTimmers/heimdall/internal/logger"
	"github.com/MatheusTimmers/heimdall/internal/parser"
)

func main() {
	capture, err := capture.Start("tun0")
	defer capture.Stop()
	if err != nil {
		log.Fatalf("falha na captura: %v", err)
	}

	for raw := range capture.Packets {
		pkg, err := parser.Parse(raw)
		if err != nil {
			log.Printf("parser erro: %v", err)
			continue
		}

		logger.Log(pkg)
	}
}
