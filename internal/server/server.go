package server

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"dns/internal/dnsmsg"
)

type Server struct {
	Addr      string
	Resolver  *Resolver
	Forwarder *Forwarder
	Logger    *log.Logger
	Verbose   bool

	TCPIdleTimeout time.Duration
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = log.Default()
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", s.Addr)
	if err != nil {
		udp.Close()
		return err
	}
	s.Logger.Printf("listening on %s (udp+tcp)", s.Addr)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.serveUDP(udp) }()
	go func() { defer wg.Done(); s.serveTCP(tcp) }()
	<-ctx.Done()
	udp.Close()
	tcp.Close()
	wg.Wait()
	return nil
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, dnsmsg.MaxEDNSSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Logger.Printf("udp read: %v", err)
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			resp := s.Handle(query, false, addr)
			if resp != nil {
				conn.WriteToUDP(resp, addr)
			}
		}()
	}
}

func (s *Server) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Logger.Printf("tcp accept: %v", err)
			continue
		}
		go s.serveTCPConn(conn)
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	idle := s.TCPIdleTimeout
	if idle == 0 {
		idle = 10 * time.Second
	}
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		query, err := readTCP(conn)
		if err != nil {
			return
		}
		resp := s.Handle(query, true, conn.RemoteAddr())
		if resp == nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(idle))
		if err := writeTCP(conn, resp); err != nil {
			return
		}
	}
}

func (s *Server) Handle(query []byte, viaTCP bool, from net.Addr) []byte {
	msg, err := dnsmsg.Parse(query)
	if err != nil {
		if msg == nil || msg.Header.QR() {
			return nil
		}
		s.logf("%s FORMERR (%v)", from, err)
		return s.errorResponse(msg, dnsmsg.RcodeFormErr)
	}
	if msg.Header.QR() {
		return nil
	}

	resp, forward := s.Resolver.Resolve(msg, s.Forwarder != nil && s.Forwarder.Upstream != "")
	if forward {
		upstream, err := s.Forwarder.Forward(query, viaTCP)
		if err != nil {
			s.logf("%s %s -> upstream error: %v", from, msg.Questions[0], err)
			return s.errorResponse(msg, dnsmsg.RcodeServFail)
		}
		s.logf("%s %s -> forwarded to %s", from, msg.Questions[0], s.Forwarder.Upstream)
		return upstream
	}

	if len(msg.Questions) == 1 {
		s.logf("%s %s -> %s, %d answer(s)", from, msg.Questions[0], dnsmsg.RcodeName(resp.Header.Rcode()), len(resp.Answers))
	}
	out, err := resp.Pack()
	if err != nil {
		s.logf("pack: %v", err)
		return s.errorResponse(msg, dnsmsg.RcodeServFail)
	}
	if !viaTCP && len(out) > msg.UDPSize() {
		out, err = resp.Truncated().Pack()
		if err != nil {
			return nil
		}
	}
	return out
}

func (s *Server) errorResponse(q *dnsmsg.Message, rcode uint8) []byte {
	resp := &dnsmsg.Message{
		Header:    dnsmsg.Header{ID: q.Header.ID, Flags: dnsmsg.FlagQR | q.Header.Flags&dnsmsg.FlagRD},
		Questions: q.Questions,
	}
	resp.Header.SetRcode(rcode)
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func (s *Server) logf(format string, args ...any) {
	if s.Verbose && s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}
