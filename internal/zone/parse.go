package zone

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"dns/internal/dnsmsg"
)

const DefaultTTL = 300

type Options struct {
	DefaultTTL uint32
	AutoPTR    bool
}

func LoadFile(path string, opts Options) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f, opts)
}

func Load(r io.Reader, opts Options) (*Zone, error) {
	if opts.DefaultTTL == 0 {
		opts.DefaultTTL = DefaultTTL
	}
	z := New()
	ttl := opts.DefaultTTL
	origin := "."
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for ln := 1; sc.Scan(); ln++ {
		tokens, err := tokenize(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
		if len(tokens) == 0 {
			continue
		}
		switch strings.ToUpper(tokens[0]) {
		case "$TTL":
			if len(tokens) != 2 {
				return nil, fmt.Errorf("line %d: $TTL expects one value", ln)
			}
			v, err := parseTTL(tokens[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", ln, err)
			}
			ttl = v
			continue
		case "$ORIGIN":
			if len(tokens) != 2 {
				return nil, fmt.Errorf("line %d: $ORIGIN expects one value", ln)
			}
			origin = dnsmsg.Canonical(tokens[1])
			continue
		}
		rr, err := parseRecord(tokens, origin, ttl)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
		z.Add(rr)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if opts.AutoPTR {
		z.addReverse()
	}
	return z, nil
}

func parseRecord(tokens []string, origin string, defaultTTL uint32) (dnsmsg.RR, error) {
	if len(tokens) < 3 {
		return dnsmsg.RR{}, fmt.Errorf("expected: <name> [ttl] <type> <value...>")
	}
	rr := dnsmsg.RR{Name: qualify(tokens[0], origin), Class: dnsmsg.ClassIN, TTL: defaultTTL}
	rest := tokens[1:]
	if v, err := parseTTL(rest[0]); err == nil {
		rr.TTL = v
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return dnsmsg.RR{}, fmt.Errorf("missing record type or value")
	}
	if strings.EqualFold(rest[0], "IN") {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return dnsmsg.RR{}, fmt.Errorf("missing record value")
	}
	t, ok := dnsmsg.TypeByName(rest[0])
	if !ok {
		return dnsmsg.RR{}, fmt.Errorf("unknown record type %q", rest[0])
	}
	rr.Type = t
	data, err := parseRData(t, rest[1:], origin)
	if err != nil {
		return dnsmsg.RR{}, fmt.Errorf("%s: %w", rest[0], err)
	}
	rr.Data = data
	return rr, nil
}

func parseRData(t uint16, args []string, origin string) (dnsmsg.RData, error) {
	name := func(i int) string { return qualify(args[i], origin) }
	switch t {
	case dnsmsg.TypeA:
		addr, err := parseAddr(args, 4)
		if err != nil {
			return nil, err
		}
		return dnsmsg.A{Addr: addr}, nil
	case dnsmsg.TypeAAAA:
		addr, err := parseAddr(args, 16)
		if err != nil {
			return nil, err
		}
		return dnsmsg.AAAA{Addr: addr}, nil
	case dnsmsg.TypeCNAME:
		if len(args) != 1 {
			return nil, fmt.Errorf("expected one target name")
		}
		return dnsmsg.CNAME{Target: name(0)}, nil
	case dnsmsg.TypeNS:
		if len(args) != 1 {
			return nil, fmt.Errorf("expected one host name")
		}
		return dnsmsg.NS{Host: name(0)}, nil
	case dnsmsg.TypePTR:
		if len(args) != 1 {
			return nil, fmt.Errorf("expected one target name")
		}
		return dnsmsg.PTR{Target: name(0)}, nil
	case dnsmsg.TypeMX:
		if len(args) != 2 {
			return nil, fmt.Errorf("expected <preference> <exchange>")
		}
		pref, err := parseU16(args[0])
		if err != nil {
			return nil, err
		}
		return dnsmsg.MX{Preference: pref, Exchange: name(1)}, nil
	case dnsmsg.TypeTXT:
		if len(args) == 0 {
			return nil, fmt.Errorf("expected at least one string")
		}
		return dnsmsg.TXT{Strings: append([]string(nil), args...)}, nil
	case dnsmsg.TypeSOA:
		if len(args) != 7 {
			return nil, fmt.Errorf("expected <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>")
		}
		soa := dnsmsg.SOA{MName: name(0), RName: name(1)}
		for i, f := range []*uint32{&soa.Serial, &soa.Refresh, &soa.Retry, &soa.Expire, &soa.Minimum} {
			v, err := parseTTL(args[2+i])
			if err != nil {
				return nil, err
			}
			*f = v
		}
		return soa, nil
	case dnsmsg.TypeSRV:
		if len(args) != 4 {
			return nil, fmt.Errorf("expected <priority> <weight> <port> <target>")
		}
		srv := dnsmsg.SRV{Target: name(3)}
		for i, f := range []*uint16{&srv.Priority, &srv.Weight, &srv.Port} {
			v, err := parseU16(args[i])
			if err != nil {
				return nil, err
			}
			*f = v
		}
		return srv, nil
	case dnsmsg.TypeHINFO:
		if len(args) != 2 {
			return nil, fmt.Errorf("expected <cpu> <os>")
		}
		return dnsmsg.HINFO{CPU: args[0], OS: args[1]}, nil
	case dnsmsg.TypeCAA:
		if len(args) != 3 {
			return nil, fmt.Errorf("expected <flags> <tag> <value>")
		}
		flags, err := strconv.ParseUint(args[0], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("bad flags %q", args[0])
		}
		return dnsmsg.CAA{Flags: uint8(flags), Tag: args[1], Value: args[2]}, nil
	}
	return nil, fmt.Errorf("type not supported in config")
}

func parseAddr(args []string, size int) (netip.Addr, error) {
	if len(args) != 1 {
		return netip.Addr{}, fmt.Errorf("expected one address")
	}
	addr, err := netip.ParseAddr(args[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bad address %q", args[0])
	}
	addr = addr.Unmap()
	if addr.BitLen()/8 != size {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv%d address", args[0], size*2-2)
	}
	return addr, nil
}

func parseU16(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("bad number %q", s)
	}
	return uint16(v), nil
}

func parseTTL(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty ttl")
	}
	units := map[byte]uint32{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	var total uint64
	num := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			num += string(c)
			continue
		}
		mult, ok := units[c|0x20]
		if !ok || num == "" {
			return 0, fmt.Errorf("bad ttl %q", s)
		}
		v, _ := strconv.ParseUint(num, 10, 32)
		total += v * uint64(mult)
		num = ""
	}
	if num != "" {
		v, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("bad ttl %q", s)
		}
		total += v
	}
	if total > 1<<31-1 {
		return 0, fmt.Errorf("ttl %q too large", s)
	}
	return uint32(total), nil
}

func qualify(name, origin string) string {
	if name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") || origin == "." {
		return dnsmsg.Canonical(name)
	}
	return dnsmsg.Canonical(name + "." + origin)
}

func tokenize(line string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inQuote, inToken := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote:
			switch c {
			case '"':
				inQuote = false
			case '\\':
				if i+1 < len(line) {
					i++
					cur.WriteByte(line[i])
				}
			default:
				cur.WriteByte(c)
			}
		case c == '"':
			inQuote, inToken = true, true
		case c == '#' || c == ';':
			if inToken {
				tokens = append(tokens, cur.String())
			}
			return tokens, nil
		case c == ' ' || c == '\t' || c == '\r':
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			inToken = true
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}
