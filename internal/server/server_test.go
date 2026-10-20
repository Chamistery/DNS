package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"dns/internal/dnsmsg"
	"dns/internal/zone"
)

var conf = `
example.com   A     93.184.216.34
$ORIGIN lab.test.
@      SOA   ns1 hostmaster 1 3600 600 86400 300
@      NS    ns1
ns1    A     10.1.0.1
@      A     10.1.0.10
www    CNAME @
alias  CNAME www
ext    CNAME example.com.
out    CNAME nowhere.invalid.
@      MX    10 mail
mail   A     10.1.0.20
big    TXT   "` + strings.Repeat("x", 250) + `"
big    TXT   "` + strings.Repeat("y", 250) + `"
big    TXT   "` + strings.Repeat("z", 250) + `"
`

func newServer(t *testing.T, upstream string) *Server {
	t.Helper()
	z, err := zone.Load(strings.NewReader(conf), zone.Options{AutoPTR: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Resolver: &Resolver{Zone: z}}
	if upstream != "" {
		s.Forwarder = &Forwarder{Upstream: upstream}
	}
	return s
}

func query(t *testing.T, s *Server, name string, qtype uint16, tcp bool, edns bool) *dnsmsg.Message {
	t.Helper()
	q := &dnsmsg.Message{
		Header:    dnsmsg.Header{ID: 42, Flags: dnsmsg.FlagRD},
		Questions: []dnsmsg.Question{{Name: name, Type: qtype, Class: dnsmsg.ClassIN}},
	}
	if edns {
		q.EDNS = &dnsmsg.OPT{UDPSize: 4096}
	}
	buf, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out := s.Handle(buf, tcp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if out == nil {
		t.Fatalf("no response for %s", name)
	}
	resp, err := dnsmsg.Parse(out)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Header.ID != 42 || !resp.Header.QR() {
		t.Fatalf("bad header %+v", resp.Header)
	}
	return resp
}

func TestAnswersA(t *testing.T) {
	resp := query(t, newServer(t, ""), "EXAMPLE.COM", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeNoError || len(resp.Answers) != 1 {
		t.Fatalf("resp: %+v", resp)
	}
	if resp.Header.Flags&dnsmsg.FlagAA == 0 {
		t.Fatal("expected AA")
	}
	if resp.Answers[0].Data.String() != "93.184.216.34" {
		t.Fatalf("answer: %s", resp.Answers[0])
	}
}

func TestCNAMEChainAndGlue(t *testing.T) {
	s := newServer(t, "")
	resp := query(t, s, "alias.lab.test.", dnsmsg.TypeA, false, false)
	if len(resp.Answers) != 3 || resp.Answers[0].Type != dnsmsg.TypeCNAME || resp.Answers[2].Type != dnsmsg.TypeA {
		t.Fatalf("chain: %+v", resp.Answers)
	}
	resp = query(t, s, "lab.test.", dnsmsg.TypeMX, false, false)
	if len(resp.Additional) != 1 || resp.Additional[0].Name != "mail.lab.test." {
		t.Fatalf("glue: %+v", resp.Additional)
	}
	resp = query(t, s, "www.lab.test.", dnsmsg.TypeCNAME, false, false)
	if len(resp.Answers) != 1 || resp.Answers[0].Type != dnsmsg.TypeCNAME {
		t.Fatalf("explicit CNAME query: %+v", resp.Answers)
	}
}

func TestNegativeResponses(t *testing.T) {
	s := newServer(t, "")
	resp := query(t, s, "missing.lab.test.", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeNXDomain || len(resp.Authority) != 1 || resp.Authority[0].Type != dnsmsg.TypeSOA {
		t.Fatalf("nxdomain: %+v", resp)
	}
	resp = query(t, s, "lab.test.", dnsmsg.TypeAAAA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeNoError || len(resp.Answers) != 0 || len(resp.Authority) != 1 {
		t.Fatalf("nodata: %+v", resp)
	}
	resp = query(t, s, "unknown.example.org.", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeRefused {
		t.Fatalf("expected REFUSED without upstream, got %s", dnsmsg.RcodeName(resp.Header.Rcode()))
	}
	resp = query(t, s, "out.lab.test.", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeNoError || len(resp.Answers) != 1 || resp.Answers[0].Type != dnsmsg.TypeCNAME {
		t.Fatalf("dangling cname: %+v", resp)
	}
}

func TestANYAndPTR(t *testing.T) {
	s := newServer(t, "")
	resp := query(t, s, "lab.test.", dnsmsg.TypeANY, false, false)
	if len(resp.Answers) != 4 {
		t.Fatalf("any: %+v", resp.Answers)
	}
	resp = query(t, s, "20.0.1.10.in-addr.arpa.", dnsmsg.TypePTR, false, false)
	if len(resp.Answers) != 1 || resp.Answers[0].Data.String() != "mail.lab.test." {
		t.Fatalf("ptr: %+v", resp.Answers)
	}
}

func TestTruncation(t *testing.T) {
	s := newServer(t, "")
	resp := query(t, s, "big.lab.test.", dnsmsg.TypeTXT, false, false)
	if !resp.Header.TC() || len(resp.Answers) != 0 {
		t.Fatalf("expected TC over plain UDP, got %+v", resp.Header)
	}
	resp = query(t, s, "big.lab.test.", dnsmsg.TypeTXT, false, true)
	if resp.Header.TC() || len(resp.Answers) != 3 || resp.EDNS == nil {
		t.Fatalf("expected full answer with EDNS, got %+v", resp.Header)
	}
	resp = query(t, s, "big.lab.test.", dnsmsg.TypeTXT, true, false)
	if resp.Header.TC() || len(resp.Answers) != 3 {
		t.Fatalf("expected full answer over TCP, got %+v", resp.Header)
	}
}

func TestForwarding(t *testing.T) {
	upstream := newServer(t, "")
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := upstream.Handle(buf[:n], false, addr); out != nil {
				ln.WriteTo(out, addr)
			}
		}
	}()
	s := newServer(t, ln.LocalAddr().String())
	resp := query(t, s, "example.com.", dnsmsg.TypeA, false, false)
	if resp.Header.Flags&dnsmsg.FlagRA == 0 {
		t.Fatal("expected RA with upstream")
	}
	resp = query(t, s, "ext.lab.test.", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeNoError {
		t.Fatalf("external cname target via upstream: %s", dnsmsg.RcodeName(resp.Header.Rcode()))
	}
	s.Forwarder.Upstream = "127.0.0.1:1"
	s.Forwarder.Timeout = 200 * time.Millisecond
	resp = query(t, s, "missing.example.org.", dnsmsg.TypeA, false, false)
	if resp.Header.Rcode() != dnsmsg.RcodeServFail {
		t.Fatalf("dead upstream: %s", dnsmsg.RcodeName(resp.Header.Rcode()))
	}
}

func TestMalformedQueries(t *testing.T) {
	s := newServer(t, "")
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if out := s.Handle([]byte{1, 2, 3}, false, from); out != nil {
		t.Fatal("garbage must be dropped")
	}
	resp := &dnsmsg.Message{Header: dnsmsg.Header{ID: 7, Flags: dnsmsg.FlagQR}}
	buf, _ := resp.Pack()
	if out := s.Handle(buf, false, from); out != nil {
		t.Fatal("responses must be dropped")
	}
	q := &dnsmsg.Message{Header: dnsmsg.Header{ID: 7, Flags: 2 << 11}, Questions: []dnsmsg.Question{{Name: "a.", Type: dnsmsg.TypeA, Class: dnsmsg.ClassIN}}}
	buf, _ = q.Pack()
	got, _ := dnsmsg.Parse(s.Handle(buf, false, from))
	if got.Header.Rcode() != dnsmsg.RcodeNotImpl {
		t.Fatalf("status opcode: %s", dnsmsg.RcodeName(got.Header.Rcode()))
	}
}
