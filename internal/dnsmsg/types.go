package dnsmsg

import (
	"fmt"
	"strings"
)

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeHINFO uint16 = 13
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeCAA   uint16 = 257
	TypeANY   uint16 = 255

	ClassIN  uint16 = 1
	ClassANY uint16 = 255

	RcodeNoError  uint8 = 0
	RcodeFormErr  uint8 = 1
	RcodeServFail uint8 = 2
	RcodeNXDomain uint8 = 3
	RcodeNotImpl  uint8 = 4
	RcodeRefused  uint8 = 5

	FlagQR uint16 = 1 << 15
	FlagAA uint16 = 1 << 10
	FlagTC uint16 = 1 << 9
	FlagRD uint16 = 1 << 8
	FlagRA uint16 = 1 << 7

	MaxUDPSize  = 512
	MaxEDNSSize = 4096
	MaxMsgSize  = 65535
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeHINFO: "HINFO", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV",
	TypeOPT: "OPT", TypeCAA: "CAA", TypeANY: "ANY",
}

var typeValues = func() map[string]uint16 {
	m := make(map[string]uint16, len(typeNames))
	for v, n := range typeNames {
		m[n] = v
	}
	return m
}()

func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

func TypeByName(name string) (uint16, bool) {
	t, ok := typeValues[strings.ToUpper(name)]
	return t, ok
}

func RcodeName(rc uint8) string {
	switch rc {
	case RcodeNoError:
		return "NOERROR"
	case RcodeFormErr:
		return "FORMERR"
	case RcodeServFail:
		return "SERVFAIL"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNotImpl:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", rc)
}
