package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"dns/internal/dnsmsg"
)

type Forwarder struct {
	Upstream string
	Timeout  time.Duration
}

func (f *Forwarder) Forward(query []byte, viaTCP bool) ([]byte, error) {
	if f == nil || f.Upstream == "" {
		return nil, errors.New("no upstream configured")
	}
	if viaTCP {
		return f.tcp(query)
	}
	resp, err := f.udp(query)
	if err != nil {
		return nil, err
	}
	h, err := dnsmsg.ParseHeader(resp)
	if err == nil && h.TC() {
		if tcpResp, err := f.tcp(query); err == nil {
			return tcpResp, nil
		}
	}
	return resp, nil
}

func (f *Forwarder) udp(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", f.Upstream, f.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(f.Timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsmsg.MaxEDNSSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (f *Forwarder) tcp(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", f.Upstream, f.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(f.Timeout))
	if err := writeTCP(conn, query); err != nil {
		return nil, err
	}
	return readTCP(conn)
}

func writeTCP(w io.Writer, msg []byte) error {
	if len(msg) > dnsmsg.MaxMsgSize {
		return dnsmsg.ErrTooBig
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

func readTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("empty tcp dns message")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
