package logger

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/MatheusTimmers/heimdall/internal/parser"
)

type Logger struct {
	writer *csv.Writer
	file   *os.File
	mu     sync.Mutex
}

type Layer2Logger struct{ *Logger }

type Layer3Logger struct{ *Logger }

type Layer4Logger struct{ *Logger }

func newLogger(path string, header []string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(file)
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() == 0 {
		if err = writer.Write(header); err != nil {
			return nil, err
		}
		writer.Flush()
	}

	return &Logger{
		writer: writer,
		file:   file,
		mu:     sync.Mutex{},
	}, nil
}

func NewLayer2Logger(path string) (*Layer2Logger, error) {
	header := []string{"Timestamp", "SrcMAC", "DstMAC", "EtherType", "PacketLength"}
	l, err := newLogger(path, header)
	if err != nil {
		return nil, err
	}

	return &Layer2Logger{l}, nil
}

func NewLayer3Logger(path string) (*Layer3Logger, error) {
	header := []string{"Timestamp", "ProtocolName", "SrcIP", "DstIP", "ProtocolID", "PacketLength"}
	l, err := newLogger(path, header)
	if err != nil {
		return nil, err
	}

	return &Layer3Logger{l}, nil
}

func NewLayer4Logger(path string) (*Layer4Logger, error) {
	header := []string{"Timestamp", "ProtocolName", "SrcIP", "SrcPort", "DstIP", "DstPort", "PacketLength"}
	l, err := newLogger(path, header)
	if err != nil {
		return nil, err
	}

	return &Layer4Logger{l}, nil
}

func (l *Layer2Logger) Log(p parser.Layer2Info) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := []string{
		p.Timestamp.Format(time.RFC3339Nano),
		p.SrcMAC,
		p.DstMAC,
		fmt.Sprintf("%#x", uint16(p.EtherType)),
		fmt.Sprintf("%d", p.PacketLength),
	}

	if err := l.writer.Write(rec); err != nil {
		return err
	}

	l.writer.Flush()
	return nil
}

func (l *Layer3Logger) Log(p parser.Layer3Info) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := []string{
		p.Timestamp.Format(time.RFC3339Nano),
		p.ProtocolName,
		p.SrcIP.String(),
		p.DstIP.String(),
		fmt.Sprintf("%d", p.Protocol),
		fmt.Sprintf("%d", p.PacketLength),
	}

	if err := l.writer.Write(rec); err != nil {
		return err
	}

	l.writer.Flush()
	return nil
}

func (l *Layer4Logger) Log(p parser.Layer4Info) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := []string{
		p.Timestamp.Format(time.RFC3339Nano),
		p.ProtocolName,
		p.SrcIP.String(),
		fmt.Sprintf("%d", p.SrcPort),
		p.DstIP.String(),
		fmt.Sprintf("%d", p.DstPort),
		fmt.Sprintf("%d", p.PacketLength),
	}

	if err := l.writer.Write(rec); err != nil {
		return err
	}

	l.writer.Flush()
	return nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer.Flush()
	return l.file.Close()
}
