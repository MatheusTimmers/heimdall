package logger

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/MatheusTimmers/heimdall/internal/parser"
)

var (
	csvWriter *csv.Writer
	initOnce  sync.Once
	mu        sync.Mutex
)

func Init(path string) error {
	var err error
	initOnce.Do(func() {
		file, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if e != nil {
			err = e
			return
		}

		csvWriter = csv.NewWriter(file)
		info, e := file.Stat()
		if e != nil {
			err = e
			return
		}

		if info.Size() == 0 {
			header := []string{"Timestamp", "SrcMAC", "DstMAC", "EtherType", "SrcIP", "DstIP", "Protocol", "SrcPort", "DstPort"}
			if e = csvWriter.Write(header); e != nil {
				err = e
				return
			}
			csvWriter.Flush()
		}
	})
	return err
}

func Log(p parser.PacketInfo) error {
	mu.Lock()
	defer mu.Unlock()

	if csvWriter == nil {
		return fmt.Errorf("logger not initialized, call Init() first")
	}

	rec := []string{
		p.Timestamp.Format(time.RFC3339Nano),
		p.SrcMAC,
		p.DstMAC,
		fmt.Sprintf("%#x", uint16(p.EtherType)),
		p.SrcIP.String(),
		p.DstIP.String(),
		fmt.Sprintf("%d", p.Protocol),
		fmt.Sprintf("%d", p.SrcPort),
		fmt.Sprintf("%d", p.DstPort),
	}

	if err := csvWriter.Write(rec); err != nil {
		return err
	}

	csvWriter.Flush()
	return nil
}
