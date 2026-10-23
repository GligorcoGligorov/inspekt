// Package authtest provides an in-memory DNS for tests of auth and the
// checks built on it. No test should depend on the network.
package authtest

import (
	"context"
	"net"
	"strings"
)

// DNS answers from maps. Names are matched case-insensitively and without
// a trailing dot. A name in Temp fails with a temporary error; any other
// unknown name is NXDOMAIN.
type DNS struct {
	TXT  map[string][]string
	IP   map[string][]net.IP
	Temp map[string]bool
}

func key(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (d *DNS) err(name string) error {
	if d.Temp[key(name)] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (d *DNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := d.TXT[key(name)]; ok && !d.Temp[key(name)] {
		return v, nil
	}
	return nil, d.err(name)
}

func (d *DNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := d.IP[key(host)]
	if !ok || d.Temp[key(host)] {
		return nil, d.err(host)
	}
	out := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		out[i] = net.IPAddr{IP: ip}
	}
	return out, nil
}

func (d *DNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, d.err(name)
}

func (d *DNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, d.err(addr)
}
