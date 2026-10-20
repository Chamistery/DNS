package zone

import (
	"net/netip"
	"strings"
	"testing"

	"dns/internal/dnsmsg"
)

const sample = `
$TTL 1h
example.com        A     93.184.216.34
example.com        AAAA  2606:2800:220:1:248:1893:25c8:1946
www.example.com 60 CNAME example.com   ; comment
*.dev.local        A     10.0.0.5
$ORIGIN lab.test.
@        SOA   ns1 hostmaster 1 3600 600 86400 300
@        MX    10 mail
@        TXT   "v=spf1 -all" "two words"
_sip._tcp SRV  10 60 5060 sip
@        CAA   0 issue "letsencrypt.org"
`

func load(t *testing.T, auto bool) *Zone {
	t.Helper()
	z, err := Load(strings.NewReader(sample), Options{AutoPTR: auto})
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestLoadRecords(t *testing.T) {
	z := load(t, false)
	rrs := z.Records("EXAMPLE.com")
	if len(rrs) != 2 || rrs[0].TTL != 3600 {
		t.Fatalf("example.com records: %+v", rrs)
	}
	if a := rrs[0].Data.(dnsmsg.A); a.Addr != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("A = %v", a)
	}
	cn := z.Records("www.example.com")
	if len(cn) != 1 || cn[0].TTL != 60 || cn[0].Data.(dnsmsg.CNAME).Target != "example.com." {
		t.Fatalf("cname: %+v", cn)
	}
	mx := z.Records("lab.test")[1].Data.(dnsmsg.MX)
	if mx.Preference != 10 || mx.Exchange != "mail.lab.test." {
		t.Fatalf("mx: %+v", mx)
	}
	txt := z.Records("lab.test")[2].Data.(dnsmsg.TXT)
	if len(txt.Strings) != 2 || txt.Strings[1] != "two words" {
		t.Fatalf("txt: %+v", txt)
	}
	srv := z.Records("_sip._tcp.lab.test")[0].Data.(dnsmsg.SRV)
	if srv.Port != 5060 || srv.Target != "sip.lab.test." {
		t.Fatalf("srv: %+v", srv)
	}
}

func TestWildcardLookup(t *testing.T) {
	z := load(t, false)
	rrs, ok := z.Lookup("anything.dev.local.")
	if !ok || len(rrs) != 1 || rrs[0].Name != "anything.dev.local." {
		t.Fatalf("wildcard: %v %+v", ok, rrs)
	}
	if _, ok := z.Lookup("dev.local."); ok {
		t.Fatal("wildcard must not match its own parent")
	}
}

func TestApexAndSOA(t *testing.T) {
	z := load(t, false)
	if apex, ok := z.Apex("deep.sub.lab.test."); !ok || apex != "lab.test." {
		t.Fatalf("apex: %q %v", apex, ok)
	}
	if _, ok := z.Apex("example.com."); ok {
		t.Fatal("example.com has no SOA, must not be authoritative zone")
	}
	if soa, ok := z.SOA("x.lab.test."); !ok || soa.Type != dnsmsg.TypeSOA {
		t.Fatalf("soa: %+v %v", soa, ok)
	}
}

func TestAutoPTR(t *testing.T) {
	z := load(t, true)
	rrs, ok := z.Lookup("34.216.184.93.in-addr.arpa.")
	if !ok || rrs[0].Data.(dnsmsg.PTR).Target != "example.com." {
		t.Fatalf("ptr: %v %+v", ok, rrs)
	}
	rev := ReverseName(netip.MustParseAddr("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if rev != want {
		t.Fatalf("ReverseName = %q", rev)
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"example.com A not-an-ip",
		"example.com A 2001:db8::1",
		"example.com AAAA 1.2.3.4",
		"example.com FOO 1",
		"example.com MX mail.example.com",
		"example.com TXT \"unterminated",
		"$TTL",
	}
	for _, line := range bad {
		if _, err := Load(strings.NewReader(line), Options{}); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
}

func TestParseTTL(t *testing.T) {
	cases := map[string]uint32{"300": 300, "1h": 3600, "1h30m": 5400, "2d": 172800, "1w": 604800}
	for in, want := range cases {
		got, err := parseTTL(in)
		if err != nil || got != want {
			t.Errorf("parseTTL(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}
