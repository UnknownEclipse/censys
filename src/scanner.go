package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type Capabilities uint32
type CharSet uint8

type Handshake struct {
	protoVersion  uint8
	serverVersion []byte
	threadId      uint32
	capabilities  Capabilities
	charSet       CharSet
	status        uint16
}

type packet struct {
	data []byte
}

const (
	deadline = time.Second
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
	fmt.Fprintf(w, "\tProtocol Version: %d\n", h.protoVersion)
	fmt.Fprintf(w, "\tServer Version: %s\n", h.serverVersion)
	fmt.Fprintf(w, "\tConnection ID: %d\n", h.threadId)

	c := CharsetName(h.charSet)
	if c == "" {
		fmt.Fprintf(w, "\tCharset: %x\n", h.charSet)
	} else {
		fmt.Fprintf(w, "\tCharset: %s\n", c)
	}
	fmt.Fprintf(w, "\tCapabilities: %b\n", h.capabilities)
	fmt.Fprintf(w, "\tStatus: %b\n", h.status)
}

func (h *Handshake) Dump() {
	h.Fdump(os.Stdout)
}

func readAll(conn net.Conn, buf []byte) error {
	for len(buf) != 0 {
		n, err := conn.Read(buf)
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

func readPacket(conn net.Conn) (*packet, error) {
	buf := make([]byte, 4)
	err := readAll(conn, buf)
	if err != nil {
		return nil, err
	}

	// MySQL uses little endian:
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_fixed
	// Packed size + sequence id
	hdr := binary.LittleEndian.Uint32(buf)

	packetLen, _ := splitHeader(hdr)

	p := new(packet)
	p.data = make([]byte, packetLen)

	err = readAll(conn, p.data)
	if err != nil {
		return nil, err
	}

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
	h.protoVersion = protoVer

	serVer, err := p.readCstr()
	if err != nil {
		return nil, err
	}
	h.serverVersion = serVer

	connId, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	h.threadId = connId

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
	h.charSet = CharSet(cset)

	statusFlags, err := p.readUint16()
	if err != nil {
		return nil, err
	}
	h.status = statusFlags

	capFlagsHigh, err := p.readUint16()
	if err != nil {
		return nil, err
	}
	capFlags := (uint32(capFlagsHigh) << 16) | uint32(capFlagsLow)
	h.capabilities = Capabilities(capFlags)

	return h, nil
}

func recvHandshake(conn net.Conn) (*Handshake, error) {
	p, err := readPacket(conn)
	if err != nil {
		return nil, err
	}

	return parseHandshakePacket(p)

}

func GetHandshake(addr string) (*Handshake, error) {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Limit session length to 1s for safety
	conn.SetDeadline(time.Now().Add(deadline))
	return recvHandshake(conn)
}
