package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dns/internal/server"
	"dns/internal/zone"
)

func main() {
	configPath := flag.String("config", "dns.conf", "path to the records config file")
	listen := flag.String("listen", "127.0.0.1:53", "address to listen on (udp and tcp)")
	upstream := flag.String("upstream", "auto", "upstream resolver for names not in config; \"auto\" takes the first non-loopback nameserver from /etc/resolv.conf, empty string disables forwarding")
	timeout := flag.Duration("timeout", 3*time.Second, "upstream query timeout")
	ttl := flag.Uint("ttl", zone.DefaultTTL, "default TTL for records without an explicit one (overridden by $TTL in config)")
	autoPTR := flag.Bool("auto-ptr", true, "generate PTR records for every A/AAAA record")
	quiet := flag.Bool("quiet", false, "do not log every query")
	flag.Parse()

	logger := log.New(os.Stderr, "dnsd: ", log.LstdFlags)

	z, err := zone.LoadFile(*configPath, zone.Options{DefaultTTL: uint32(*ttl), AutoPTR: *autoPTR})
	if err != nil {
		logger.Fatalf("config %s: %v", *configPath, err)
	}
	logger.Printf("loaded %d record(s) for %d name(s) from %s", z.Len(), len(z.Names()), *configPath)

	if *upstream == "auto" {
		addr, err := systemUpstream("/etc/resolv.conf")
		if err != nil {
			logger.Fatalf("-upstream auto: %v", err)
		}
		*upstream = addr
	}
	var fwd *server.Forwarder
	if *upstream != "" {
		fwd = &server.Forwarder{Upstream: *upstream, Timeout: *timeout}
		logger.Printf("forwarding unknown names to %s", *upstream)
	} else {
		logger.Printf("forwarding disabled: unknown names get REFUSED")
	}

	srv := &server.Server{
		Addr:      *listen,
		Resolver:  &server.Resolver{Zone: z},
		Forwarder: fwd,
		Logger:    logger,
		Verbose:   !*quiet,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "dnsd:", err)
		os.Exit(1)
	}
	logger.Printf("stopped")
}

func systemUpstream(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.IsLoopback() {
			continue
		}
		return net.JoinHostPort(addr.String(), "53"), nil
	}
	return "", fmt.Errorf("no usable nameserver in %s; pass -upstream explicitly", path)
}
