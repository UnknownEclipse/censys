package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"
)

type Capabilities uint32
type CharSet uint8

type Handshake struct {
	ProtoVersion  uint8
	ServerVersion []byte
	ThreadId      uint32
	Capabilities  Capabilities
	CharSet       CharSet
	Status        uint16
}

type packet struct {
	// Raw data including header
	rawData []byte
	data    []byte
}

const (
	deadline        = time.Second
	handshakeMaxLen = 256
)

var (
	ErrNotAscii       = errors.New("ErrNotAscii")
	ErrPacketTooLarge = errors.New("ErrPacketTooLarge")
)

func (p *packet) readUint8() (uint8, error) {
	b, err := p.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *packet) readUint16() (uint16, error) {
	b, err := p.read(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (p *packet) readUint32() (uint32, error) {
	b, err := p.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (p *packet) readCstr() ([]byte, error) {
	n := 0
	for {
		if len(p.data) == n {
			return nil, io.EOF
		}
		if p.data[n] == 0 {
			break
		}
		if 0x7f < p.data[n] {
			return nil, ErrNotAscii
		}
		n++
	}

	s := p.data[:n]
	p.data = p.data[n+1:]
	return s, nil
}

func (p *packet) read(n int) ([]byte, error) {
	if len(p.data) < n {
		return nil, io.EOF
	}
	b := p.data[:n]
	p.data = p.data[n:]
	return b, nil

}

func CharsetName(c CharSet) string {
	switch c {
	case 0x08:
		return "latin1_swedish_ci"
	case 0x21:
		return "utf8mb3_general_ci"
	case 0x3f:
		return "binary"
	default:
		return ""
	}
}

func (h *Handshake) Fdump(w io.Writer) {
	fmt.Fprintln(w, "Initial Handshake Information:")
	fmt.Fprintf(w, "\tProtocol Version: %d\n", h.ProtoVersion)
	fmt.Fprintf(w, "\tServer Version: %s\n", h.ServerVersion)
	fmt.Fprintf(w, "\tConnection ID: %d\n", h.ThreadId)

	c := CharsetName(h.CharSet)
	if c == "" {
		fmt.Fprintf(w, "\tCharset: %x\n", h.CharSet)
	} else {
		fmt.Fprintf(w, "\tCharset: %s\n", c)
	}
	fmt.Fprintf(w, "\tCapabilities: %b\n", h.Capabilities)
	fmt.Fprintf(w, "\tStatus: %b\n", h.Status)
}

func (h *Handshake) Dump() {
	h.Fdump(os.Stdout)
}

func readAll(r io.Reader, buf []byte) error {
	for len(buf) != 0 {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.EOF
		}
		buf = buf[n:]
	}
	return nil
}

func splitHeader(h uint32) (uint32, uint8) {
	packetLen := h & 0xffffff
	seqId := uint8(h >> 24)
	return packetLen, seqId
}

func readPacket(r io.Reader, limit uint32) (*packet, error) {
	buf := make([]byte, 4)
	err := readAll(r, buf)
	if err != nil {
		return nil, err
	}

	// MySQL uses little endian:
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_fixed
	// Packed size + sequence id
	hdr := binary.LittleEndian.Uint32(buf)

	packetLen, _ := splitHeader(hdr)

	if limit < packetLen {
		return nil, ErrPacketTooLarge
	}

	p := new(packet)
	p.data = make([]byte, packetLen)

	err = readAll(r, p.data)
	if err != nil {
		return nil, err
	}

	p.rawData = slices.Concat(buf, p.data)
	return p, nil
}

func parseHandshakePacket(p *packet) (*Handshake, error) {
	h := new(Handshake)

	protoVer, err := p.readUint8()
	if err != nil {
		return nil, err
	}
	if protoVer != 10 && protoVer != 9 {
		return nil, fmt.Errorf("invalid mysql protocol version")
	}
	h.ProtoVersion = protoVer

	serVer, err := p.readCstr()
	if err != nil {
		return nil, err
	}
	h.ServerVersion = serVer

	rId, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	h.ThreadId = rId

	// Skip 'auth-plugin-data-part-1 ' + filler
	_, err = p.read(8)
	if err != nil {
		return nil, err
	}
	filler, err := p.readUint8()
	if err != nil {
		return nil, err
	}
	if filler != 0 {
		return nil, fmt.Errorf("mysql handshake: filler byte not 0x00")
	}

	capFlagsLow, err := p.readUint16()
	if err != nil {
		return nil, err
	}

	cset, err := p.readUint8()
	if err != nil {
		return nil, err
	}
	h.CharSet = CharSet(cset)

	statusFlags, err := p.readUint16()
	if err != nil {
		return nil, err
	}
	h.Status = statusFlags

	capFlagsHigh, err := p.readUint16()
	if err != nil {
		return nil, err
	}
	capFlags := (uint32(capFlagsHigh) << 16) | uint32(capFlagsLow)
	h.Capabilities = Capabilities(capFlags)

	return h, nil
}

func GetHandshake(addr string) (*Handshake, error) {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Limit session length to 1s for safety
	c.SetDeadline(time.Now().Add(deadline))
	return GetHandshakeFromReader(c)
}

func GetHandshakeFromReader(r io.Reader) (*Handshake, error) {
	p, err := readPacket(r, handshakeMaxLen)
	if err != nil {
		return nil, err
	}
	return parseHandshakePacket(p)
}

func checkAddr(addr string, printMutex *sync.Mutex) {
	hs, err := GetHandshake(addr)

	printMutex.Lock()
	defer printMutex.Unlock()

	if err == nil {
		fmt.Printf("Address '%s' is likely a MySQL server!\n", addr)
		hs.Dump()
	} else {
		fmt.Printf("Address '%s' is likely not a MySQL server (encountered error: '%s')\n", addr, err)
	}

}

func main() {
	var wg sync.WaitGroup

	// Use a mutex to prevent printouts from being interleaved but allow network
	// requests to run concurrently
	var mtx sync.Mutex

	for i := 1; i < len(os.Args); i++ {
		wg.Add(1)

		go func(addr string) {
			defer wg.Done()
			checkAddr(addr, &mtx)
		}(os.Args[i])
	}

	wg.Wait()
}
