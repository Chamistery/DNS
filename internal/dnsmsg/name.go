package dnsmsg

import (
	"errors"
	"strings"
)

var ErrBadName = errors.New("dnsmsg: malformed domain name")

func Canonical(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func Labels(name string) []string {
	name = Canonical(name)
	if name == "." {
		return nil
	}
	return strings.Split(strings.TrimSuffix(name, "."), ".")
}

func Parent(name string) (string, bool) {
	name = Canonical(name)
	if name == "." {
		return "", false
	}
	i := strings.IndexByte(name, '.')
	if i+1 >= len(name) {
		return ".", true
	}
	return name[i+1:], true
}

func IsSubdomain(name, zone string) bool {
	name, zone = Canonical(name), Canonical(zone)
	if zone == "." {
		return true
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}
