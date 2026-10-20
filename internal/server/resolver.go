package server

import (
	"dns/internal/dnsmsg"
	"dns/internal/zone"
)

const maxCNAMEChain = 8

type Resolver struct {
	Zone *zone.Zone
}

func (r *Resolver) Resolve(q *dnsmsg.Message, canForward bool) (*dnsmsg.Message, bool) {
	resp := &dnsmsg.Message{
		Header:    dnsmsg.Header{ID: q.Header.ID, Flags: dnsmsg.FlagQR | q.Header.Flags&dnsmsg.FlagRD},
		Questions: q.Questions,
	}
	if q.EDNS != nil {
		resp.EDNS = &dnsmsg.OPT{UDPSize: dnsmsg.MaxEDNSSize}
	}
	if canForward {
		resp.Header.Flags |= dnsmsg.FlagRA
	}
	if q.Header.Opcode() != 0 {
		resp.Header.SetRcode(dnsmsg.RcodeNotImpl)
		return resp, false
	}
	if len(q.Questions) != 1 {
		resp.Header.SetRcode(dnsmsg.RcodeFormErr)
		return resp, false
	}
	question := q.Questions[0]
	if question.Class != dnsmsg.ClassIN && question.Class != dnsmsg.ClassANY {
		resp.Header.SetRcode(dnsmsg.RcodeRefused)
		return resp, false
	}
	if question.Type == dnsmsg.TypeOPT {
		resp.Header.SetRcode(dnsmsg.RcodeFormErr)
		return resp, false
	}

	name := question.Name
	for hop := 0; hop < maxCNAMEChain; hop++ {
		rrs, found := r.Zone.Lookup(name)
		if !found {
			break
		}
		resp.Header.Flags |= dnsmsg.FlagAA
		matched := false
		var cname *dnsmsg.RR
		for i := range rrs {
			rr := rrs[i]
			if rr.Type == dnsmsg.TypeCNAME && question.Type != dnsmsg.TypeCNAME && question.Type != dnsmsg.TypeANY {
				cname = &rr
				continue
			}
			if question.Type == dnsmsg.TypeANY || rr.Type == question.Type {
				resp.Answers = append(resp.Answers, rr)
				matched = true
			}
		}
		if matched {
			r.addGlue(resp)
			return resp, false
		}
		if cname == nil {
			r.addNegativeAuthority(resp, name)
			return resp, false
		}
		resp.Answers = append(resp.Answers, *cname)
		name = cname.Data.(dnsmsg.CNAME).Target
	}

	if len(resp.Answers) > 0 {
		if _, inZone := r.Zone.Apex(name); !inZone && canForward {
			return resp, true
		}
		r.addNegativeAuthority(resp, name)
		return resp, false
	}
	if _, inZone := r.Zone.Apex(name); inZone {
		resp.Header.Flags |= dnsmsg.FlagAA
		resp.Header.SetRcode(dnsmsg.RcodeNXDomain)
		r.addNegativeAuthority(resp, name)
		return resp, false
	}
	if canForward {
		return resp, true
	}
	resp.Header.SetRcode(dnsmsg.RcodeRefused)
	return resp, false
}

func (r *Resolver) addNegativeAuthority(resp *dnsmsg.Message, name string) {
	if soa, ok := r.Zone.SOA(name); ok {
		resp.Authority = append(resp.Authority, soa)
	}
}

func (r *Resolver) addGlue(resp *dnsmsg.Message) {
	seen := make(map[string]bool)
	for _, rr := range resp.Answers {
		switch rr.Type {
		case dnsmsg.TypeMX, dnsmsg.TypeSRV, dnsmsg.TypeNS:
		default:
			continue
		}
		ref, ok := rr.Data.(dnsmsg.HostRef)
		if !ok {
			continue
		}
		target := dnsmsg.Canonical(ref.Name())
		if seen[target] {
			continue
		}
		seen[target] = true
		rrs, found := r.Zone.Lookup(target)
		if !found {
			continue
		}
		for _, g := range rrs {
			if g.Type == dnsmsg.TypeA || g.Type == dnsmsg.TypeAAAA {
				resp.Additional = append(resp.Additional, g)
			}
		}
	}
}
