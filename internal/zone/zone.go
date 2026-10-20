package zone

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"dns/internal/dnsmsg"
)

type Zone struct {
	records map[string][]dnsmsg.RR
	apexes  []string
}

func New() *Zone {
	return &Zone{records: make(map[string][]dnsmsg.RR)}
}

func (z *Zone) Add(rr dnsmsg.RR) {
	rr.Name = dnsmsg.Canonical(rr.Name)
	z.records[rr.Name] = append(z.records[rr.Name], rr)
	if rr.Type == dnsmsg.TypeSOA {
		z.apexes = append(z.apexes, rr.Name)
		sort.Slice(z.apexes, func(i, j int) bool { return len(z.apexes[i]) > len(z.apexes[j]) })
	}
}

func (z *Zone) Len() int {
	n := 0
	for _, rrs := range z.records {
		n += len(rrs)
	}
	return n
}

func (z *Zone) Names() []string {
	names := make([]string, 0, len(z.records))
	for n := range z.records {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (z *Zone) Records(name string) []dnsmsg.RR {
	return z.records[dnsmsg.Canonical(name)]
}

func (z *Zone) Lookup(name string) ([]dnsmsg.RR, bool) {
	name = dnsmsg.Canonical(name)
	if rrs, ok := z.records[name]; ok {
		return rrs, true
	}
	if strings.HasPrefix(name, "*.") {
		return nil, false
	}
	for parent, ok := dnsmsg.Parent(name); ok; parent, ok = dnsmsg.Parent(parent) {
		wildcard := "*." + strings.TrimPrefix(parent, ".")
		if parent == "." {
			wildcard = "*."
		}
		rrs, ok := z.records[wildcard]
		if !ok {
			continue
		}
		out := make([]dnsmsg.RR, len(rrs))
		for i, rr := range rrs {
			rr.Name = name
			out[i] = rr
		}
		return out, true
	}
	return nil, false
}

func (z *Zone) Apex(name string) (string, bool) {
	for _, apex := range z.apexes {
		if dnsmsg.IsSubdomain(name, apex) {
			return apex, true
		}
	}
	return "", false
}

func (z *Zone) SOA(name string) (dnsmsg.RR, bool) {
	apex, ok := z.Apex(name)
	if !ok {
		return dnsmsg.RR{}, false
	}
	for _, rr := range z.records[apex] {
		if rr.Type == dnsmsg.TypeSOA {
			return rr, true
		}
	}
	return dnsmsg.RR{}, false
}

func (z *Zone) addReverse() {
	for _, name := range z.Names() {
		for _, rr := range z.records[name] {
			var addr netip.Addr
			switch d := rr.Data.(type) {
			case dnsmsg.A:
				addr = d.Addr
			case dnsmsg.AAAA:
				addr = d.Addr
			default:
				continue
			}
			rev := ReverseName(addr)
			if _, exists := z.records[rev]; exists {
				continue
			}
			z.records[rev] = []dnsmsg.RR{{Name: rev, Type: dnsmsg.TypePTR, Class: dnsmsg.ClassIN, TTL: rr.TTL, Data: dnsmsg.PTR{Target: rr.Name}}}
		}
	}
}

func ReverseName(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := addr.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0xF, b[i]>>4)
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}
