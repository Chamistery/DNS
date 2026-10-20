package dnsmsg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	ErrShort     = errors.New("dnsmsg: message too short")
	ErrTooBig    = errors.New("dnsmsg: message exceeds 65535 bytes")
	ErrBadLabel  = errors.New("dnsmsg: label exceeds 63 bytes")
	ErrBadString = errors.New("dnsmsg: character string exceeds 255 bytes")
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h Header) Opcode() uint8 { return uint8(h.Flags>>11) & 0xF }
func (h Header) Rcode() uint8  { return uint8(h.Flags & 0xF) }
func (h Header) RD() bool      { return h.Flags&FlagRD != 0 }
func (h Header) QR() bool      { return h.Flags&FlagQR != 0 }
func (h Header) TC() bool      { return h.Flags&FlagTC != 0 }

func (h *Header) SetRcode(rc uint8) { h.Flags = h.Flags&^0xF | uint16(rc) }

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q Question) String() string {
	return fmt.Sprintf("%s %s", q.Name, TypeName(q.Type))
}

type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  RData
}

func (rr RR) String() string {
	return fmt.Sprintf("%s\t%d\tIN\t%s\t%s", rr.Name, rr.TTL, TypeName(rr.Type), rr.Data)
}

type OPT struct {
	UDPSize uint16
	Flags   uint32
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
	EDNS       *OPT
}

func (m *Message) UDPSize() int {
	if m.EDNS == nil || m.EDNS.UDPSize < MaxUDPSize {
		return MaxUDPSize
	}
	if m.EDNS.UDPSize > MaxEDNSSize {
		return MaxEDNSSize
	}
	return int(m.EDNS.UDPSize)
}

type parser struct {
	buf []byte
	off int
}

func Parse(buf []byte) (*Message, error) {
	p := &parser{buf: buf}
	m := &Message{}
	var err error
	if m.Header, err = p.header(); err != nil {
		return nil, err
	}
	for i := 0; i < int(m.Header.QDCount); i++ {
		q, err := p.question()
		if err != nil {
			return m, err
		}
		m.Questions = append(m.Questions, q)
	}
	sections := []struct {
		n   uint16
		dst *[]RR
	}{{m.Header.ANCount, &m.Answers}, {m.Header.NSCount, &m.Authority}, {m.Header.ARCount, &m.Additional}}
	for _, s := range sections {
		for i := 0; i < int(s.n); i++ {
			rr, err := p.rr()
			if err != nil {
				return m, err
			}
			if rr.Type == TypeOPT {
				m.EDNS = &OPT{UDPSize: rr.Class, Flags: rr.TTL}
				continue
			}
			*s.dst = append(*s.dst, rr)
		}
	}
	return m, nil
}

func ParseHeader(buf []byte) (Header, error) {
	return (&parser{buf: buf}).header()
}

func (p *parser) need(n int) error {
	if p.off+n > len(p.buf) {
		return ErrShort
	}
	return nil
}

func (p *parser) u8() (uint8, error) {
	if err := p.need(1); err != nil {
		return 0, err
	}
	v := p.buf[p.off]
	p.off++
	return v, nil
}

func (p *parser) u16() (uint16, error) {
	if err := p.need(2); err != nil {
		return 0, err
	}
	v := uint16(p.buf[p.off])<<8 | uint16(p.buf[p.off+1])
	p.off += 2
	return v, nil
}

func (p *parser) u32() (uint32, error) {
	if err := p.need(4); err != nil {
		return 0, err
	}
	v := uint32(p.buf[p.off])<<24 | uint32(p.buf[p.off+1])<<16 | uint32(p.buf[p.off+2])<<8 | uint32(p.buf[p.off+3])
	p.off += 4
	return v, nil
}

func (p *parser) header() (Header, error) {
	var h Header
	var err error
	fields := []*uint16{&h.ID, &h.Flags, &h.QDCount, &h.ANCount, &h.NSCount, &h.ARCount}
	for _, f := range fields {
		if *f, err = p.u16(); err != nil {
			return h, err
		}
	}
	return h, nil
}

func (p *parser) name() (string, error) {
	var sb strings.Builder
	off := p.off
	jumped := false
	hops := 0
	for {
		if off >= len(p.buf) {
			return "", ErrShort
		}
		l := int(p.buf[off])
		switch {
		case l == 0:
			if !jumped {
				p.off = off + 1
			}
			if sb.Len() == 0 {
				return ".", nil
			}
			return sb.String(), nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(p.buf) {
				return "", ErrShort
			}
			ptr := int(p.buf[off]&0x3F)<<8 | int(p.buf[off+1])
			if ptr >= off || hops > 64 {
				return "", ErrBadName
			}
			if !jumped {
				p.off = off + 2
				jumped = true
			}
			off = ptr
			hops++
		case l&0xC0 != 0:
			return "", ErrBadName
		default:
			if off+1+l > len(p.buf) {
				return "", ErrShort
			}
			sb.Write(p.buf[off+1 : off+1+l])
			sb.WriteByte('.')
			off += 1 + l
			if sb.Len() > 255 {
				return "", ErrBadName
			}
		}
	}
}

func (p *parser) question() (Question, error) {
	var q Question
	var err error
	if q.Name, err = p.name(); err != nil {
		return q, err
	}
	q.Name = Canonical(q.Name)
	if q.Type, err = p.u16(); err != nil {
		return q, err
	}
	if q.Class, err = p.u16(); err != nil {
		return q, err
	}
	return q, nil
}

func (p *parser) charString() (string, error) {
	l, err := p.u8()
	if err != nil {
		return "", err
	}
	if err := p.need(int(l)); err != nil {
		return "", err
	}
	s := string(p.buf[p.off : p.off+int(l)])
	p.off += int(l)
	return s, nil
}

func (p *parser) rr() (RR, error) {
	var rr RR
	var err error
	if rr.Name, err = p.name(); err != nil {
		return rr, err
	}
	if rr.Type, err = p.u16(); err != nil {
		return rr, err
	}
	if rr.Class, err = p.u16(); err != nil {
		return rr, err
	}
	if rr.TTL, err = p.u32(); err != nil {
		return rr, err
	}
	rdlen, err := p.u16()
	if err != nil {
		return rr, err
	}
	if err := p.need(int(rdlen)); err != nil {
		return rr, err
	}
	end := p.off + int(rdlen)
	rr.Data, err = p.rdata(rr.Type, end)
	if err != nil {
		return rr, err
	}
	p.off = end
	return rr, nil
}

func (p *parser) rdata(t uint16, end int) (RData, error) {
	raw := p.buf[p.off:end]
	switch t {
	case TypeA:
		if len(raw) != 4 {
			return nil, ErrShort
		}
		return A{Addr: netip.AddrFrom4([4]byte(raw))}, nil
	case TypeAAAA:
		if len(raw) != 16 {
			return nil, ErrShort
		}
		return AAAA{Addr: netip.AddrFrom16([16]byte(raw))}, nil
	case TypeCNAME, TypeNS, TypePTR:
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		switch t {
		case TypeCNAME:
			return CNAME{Target: n}, nil
		case TypeNS:
			return NS{Host: n}, nil
		default:
			return PTR{Target: n}, nil
		}
	case TypeMX:
		pref, err := p.u16()
		if err != nil {
			return nil, err
		}
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		return MX{Preference: pref, Exchange: n}, nil
	case TypeTXT:
		var ss []string
		for p.off < end {
			s, err := p.charString()
			if err != nil {
				return nil, err
			}
			ss = append(ss, s)
		}
		return TXT{Strings: ss}, nil
	case TypeSOA:
		var soa SOA
		var err error
		if soa.MName, err = p.name(); err != nil {
			return nil, err
		}
		if soa.RName, err = p.name(); err != nil {
			return nil, err
		}
		for _, f := range []*uint32{&soa.Serial, &soa.Refresh, &soa.Retry, &soa.Expire, &soa.Minimum} {
			if *f, err = p.u32(); err != nil {
				return nil, err
			}
		}
		return soa, nil
	case TypeSRV:
		var srv SRV
		var err error
		for _, f := range []*uint16{&srv.Priority, &srv.Weight, &srv.Port} {
			if *f, err = p.u16(); err != nil {
				return nil, err
			}
		}
		if srv.Target, err = p.name(); err != nil {
			return nil, err
		}
		return srv, nil
	case TypeHINFO:
		cpu, err := p.charString()
		if err != nil {
			return nil, err
		}
		os, err := p.charString()
		if err != nil {
			return nil, err
		}
		return HINFO{CPU: cpu, OS: os}, nil
	case TypeCAA:
		if len(raw) < 2 {
			return nil, ErrShort
		}
		flags, _ := p.u8()
		tag, err := p.charString()
		if err != nil {
			return nil, err
		}
		return CAA{Flags: flags, Tag: tag, Value: string(p.buf[p.off:end])}, nil
	}
	return Raw{RType: t, Data: append([]byte(nil), raw...)}, nil
}

type packer struct {
	buf   []byte
	names map[string]int
	err   error
}

func (p *packer) u8(v uint8)   { p.buf = append(p.buf, v) }
func (p *packer) u16(v uint16) { p.buf = append(p.buf, byte(v>>8), byte(v)) }
func (p *packer) u32(v uint32) {
	p.buf = append(p.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func (p *packer) bytes(b []byte) { p.buf = append(p.buf, b...) }

func (p *packer) charString(s string) {
	if len(s) > 255 {
		p.err = ErrBadString
		s = s[:255]
	}
	p.u8(uint8(len(s)))
	p.buf = append(p.buf, s...)
}

func (p *packer) name(name string, compress bool) {
	name = Canonical(name)
	for name != "." {
		if compress {
			if off, ok := p.names[name]; ok {
				p.u16(0xC000 | uint16(off))
				return
			}
			if len(p.buf) < 0x4000 {
				p.names[name] = len(p.buf)
			}
		}
		i := strings.IndexByte(name, '.')
		label := name[:i]
		if len(label) > 63 {
			p.err = ErrBadLabel
			label = label[:63]
		}
		p.u8(uint8(len(label)))
		p.buf = append(p.buf, label...)
		name = name[i+1:]
		if name == "" {
			name = "."
		}
	}
	p.u8(0)
}

func (p *packer) rr(rr RR) {
	p.name(rr.Name, true)
	p.u16(rr.Type)
	p.u16(rr.Class)
	p.u32(rr.TTL)
	lenOff := len(p.buf)
	p.u16(0)
	rr.Data.pack(p)
	rdlen := len(p.buf) - lenOff - 2
	p.buf[lenOff] = byte(rdlen >> 8)
	p.buf[lenOff+1] = byte(rdlen)
}

func (m *Message) Pack() ([]byte, error) {
	p := &packer{buf: make([]byte, 0, 512), names: make(map[string]int)}
	h := m.Header
	h.QDCount = uint16(len(m.Questions))
	h.ANCount = uint16(len(m.Answers))
	h.NSCount = uint16(len(m.Authority))
	h.ARCount = uint16(len(m.Additional))
	if m.EDNS != nil {
		h.ARCount++
	}
	for _, v := range []uint16{h.ID, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount} {
		p.u16(v)
	}
	for _, q := range m.Questions {
		p.name(q.Name, true)
		p.u16(q.Type)
		p.u16(q.Class)
	}
	for _, section := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, rr := range section {
			p.rr(rr)
		}
	}
	if m.EDNS != nil {
		p.u8(0)
		p.u16(TypeOPT)
		p.u16(m.EDNS.UDPSize)
		p.u32(m.EDNS.Flags)
		p.u16(0)
	}
	if p.err != nil {
		return nil, p.err
	}
	if len(p.buf) > MaxMsgSize {
		return nil, ErrTooBig
	}
	return p.buf, nil
}

func (m *Message) Truncated() *Message {
	t := &Message{Header: m.Header, Questions: m.Questions, EDNS: m.EDNS}
	t.Header.Flags |= FlagTC
	return t
}
