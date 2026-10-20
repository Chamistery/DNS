package dnsmsg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type RData interface {
	Type() uint16
	String() string
	pack(p *packer)
}

type A struct{ Addr netip.Addr }
type AAAA struct{ Addr netip.Addr }
type CNAME struct{ Target string }
type NS struct{ Host string }
type PTR struct{ Target string }
type MX struct {
	Preference uint16
	Exchange   string
}
type TXT struct{ Strings []string }
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}
type SRV struct {
	Priority, Weight, Port uint16
	Target                 string
}
type HINFO struct{ CPU, OS string }
type CAA struct {
	Flags uint8
	Tag   string
	Value string
}
type Raw struct {
	RType uint16
	Data  []byte
}

func (A) Type() uint16     { return TypeA }
func (AAAA) Type() uint16  { return TypeAAAA }
func (CNAME) Type() uint16 { return TypeCNAME }
func (NS) Type() uint16    { return TypeNS }
func (PTR) Type() uint16   { return TypePTR }
func (MX) Type() uint16    { return TypeMX }
func (TXT) Type() uint16   { return TypeTXT }
func (SOA) Type() uint16   { return TypeSOA }
func (SRV) Type() uint16   { return TypeSRV }
func (HINFO) Type() uint16 { return TypeHINFO }
func (CAA) Type() uint16   { return TypeCAA }
func (r Raw) Type() uint16 { return r.RType }

func (r A) String() string     { return r.Addr.String() }
func (r AAAA) String() string  { return r.Addr.String() }
func (r CNAME) String() string { return r.Target }
func (r NS) String() string    { return r.Host }
func (r PTR) String() string   { return r.Target }
func (r MX) String() string    { return fmt.Sprintf("%d %s", r.Preference, r.Exchange) }
func (r TXT) String() string {
	parts := make([]string, len(r.Strings))
	for i, s := range r.Strings {
		parts[i] = strconv.Quote(s)
	}
	return strings.Join(parts, " ")
}
func (r SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
}
func (r SRV) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
}
func (r HINFO) String() string { return fmt.Sprintf("%q %q", r.CPU, r.OS) }
func (r CAA) String() string   { return fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value) }
func (r Raw) String() string   { return fmt.Sprintf("\\# %d %x", len(r.Data), r.Data) }

func (r A) pack(p *packer)     { a := r.Addr.As4(); p.bytes(a[:]) }
func (r AAAA) pack(p *packer)  { a := r.Addr.As16(); p.bytes(a[:]) }
func (r CNAME) pack(p *packer) { p.name(r.Target, true) }
func (r NS) pack(p *packer)    { p.name(r.Host, true) }
func (r PTR) pack(p *packer)   { p.name(r.Target, true) }
func (r MX) pack(p *packer)    { p.u16(r.Preference); p.name(r.Exchange, true) }
func (r TXT) pack(p *packer) {
	for _, s := range r.Strings {
		p.charString(s)
	}
}
func (r SOA) pack(p *packer) {
	p.name(r.MName, true)
	p.name(r.RName, true)
	p.u32(r.Serial)
	p.u32(r.Refresh)
	p.u32(r.Retry)
	p.u32(r.Expire)
	p.u32(r.Minimum)
}
func (r SRV) pack(p *packer) {
	p.u16(r.Priority)
	p.u16(r.Weight)
	p.u16(r.Port)
	p.name(r.Target, false)
}
func (r HINFO) pack(p *packer) { p.charString(r.CPU); p.charString(r.OS) }
func (r CAA) pack(p *packer) {
	p.u8(r.Flags)
	p.charString(r.Tag)
	p.bytes([]byte(r.Value))
}
func (r Raw) pack(p *packer) { p.bytes(r.Data) }

func (r CNAME) Name() string { return r.Target }
func (r NS) Name() string    { return r.Host }
func (r PTR) Name() string   { return r.Target }
func (r MX) Name() string    { return r.Exchange }
func (r SRV) Name() string   { return r.Target }

type HostRef interface{ Name() string }
