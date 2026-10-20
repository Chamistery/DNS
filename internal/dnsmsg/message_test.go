package dnsmsg

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestPackParseRoundTrip(t *testing.T) {
	msg := &Message{
		Header:    Header{ID: 0xBEEF, Flags: FlagQR | FlagAA | FlagRD},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []RR{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: A{Addr: netip.MustParseAddr("1.2.3.4")}},
			{Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 60, Data: AAAA{Addr: netip.MustParseAddr("2001:db8::1")}},
			{Name: "www.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: CNAME{Target: "example.com."}},
			{Name: "example.com.", Type: TypeMX, Class: ClassIN, TTL: 60, Data: MX{Preference: 10, Exchange: "mail.example.com."}},
			{Name: "example.com.", Type: TypeTXT, Class: ClassIN, TTL: 60, Data: TXT{Strings: []string{"v=spf1 -all", "second"}}},
			{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 60, Data: NS{Host: "ns1.example.com."}},
			{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 60, Data: SOA{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}},
			{Name: "_sip._tcp.example.com.", Type: TypeSRV, Class: ClassIN, TTL: 60, Data: SRV{Priority: 1, Weight: 2, Port: 5060, Target: "sip.example.com."}},
			{Name: "4.3.2.1.in-addr.arpa.", Type: TypePTR, Class: ClassIN, TTL: 60, Data: PTR{Target: "example.com."}},
			{Name: "example.com.", Type: TypeCAA, Class: ClassIN, TTL: 60, Data: CAA{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
			{Name: "example.com.", Type: TypeHINFO, Class: ClassIN, TTL: 60, Data: HINFO{CPU: "ARM64", OS: "macOS"}},
			{Name: "example.com.", Type: 99, Class: ClassIN, TTL: 60, Data: Raw{RType: 99, Data: []byte{1, 2, 3}}},
		},
		EDNS: &OPT{UDPSize: 4096},
	}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got, err := Parse(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Header.ID != msg.Header.ID || got.Header.Flags != msg.Header.Flags {
		t.Fatalf("header mismatch: %+v", got.Header)
	}
	if !reflect.DeepEqual(got.Questions, msg.Questions) {
		t.Fatalf("questions mismatch: %+v", got.Questions)
	}
	if !reflect.DeepEqual(got.Answers, msg.Answers) {
		t.Fatalf("answers mismatch:\n got %+v\nwant %+v", got.Answers, msg.Answers)
	}
	if got.EDNS == nil || got.EDNS.UDPSize != 4096 {
		t.Fatalf("edns lost: %+v", got.EDNS)
	}
}

func TestCompressionShrinksMessage(t *testing.T) {
	msg := &Message{Questions: []Question{{Name: "a.very.long.example.com.", Type: TypeA, Class: ClassIN}}}
	for i := 0; i < 10; i++ {
		msg.Answers = append(msg.Answers, RR{Name: "a.very.long.example.com.", Type: TypeA, Class: ClassIN, Data: A{Addr: netip.MustParseAddr("10.0.0.1")}})
	}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	uncompressed := 12 + 26 + 4 + 10*(26+10+4)
	if len(buf) >= uncompressed {
		t.Fatalf("expected compression, got %d bytes (uncompressed %d)", len(buf), uncompressed)
	}
}

func TestParseRejectsPointerLoop(t *testing.T) {
	buf := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1}
	if _, err := Parse(buf); err == nil {
		t.Fatal("expected error for self-referencing pointer")
	}
}

func TestParseShortMessage(t *testing.T) {
	if _, err := Parse([]byte{1, 2, 3}); err != ErrShort {
		t.Fatalf("got %v, want ErrShort", err)
	}
}

func TestCanonical(t *testing.T) {
	cases := map[string]string{"": ".", ".": ".", "Example.COM": "example.com.", "example.com.": "example.com."}
	for in, want := range cases {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
	if p, ok := Parent("a.b.c."); !ok || p != "b.c." {
		t.Errorf("Parent(a.b.c.) = %q, %v", p, ok)
	}
	if p, ok := Parent("c."); !ok || p != "." {
		t.Errorf("Parent(c.) = %q, %v", p, ok)
	}
	if !IsSubdomain("a.b.c.", "b.c.") || IsSubdomain("ab.c.", "b.c.") {
		t.Error("IsSubdomain wrong")
	}
}
