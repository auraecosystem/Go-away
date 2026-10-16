// Package dnstest runs a minimal DNS server on loopback for tests.
package dnstest

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

const typeA = 1

// NewServer answers A queries for the names in answers, and NXDOMAIN for any other name.
// Names are matched without the trailing dot, case-insensitively.
// It returns the server address.
func NewServer(t testing.TB, answers map[string]net.IP) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to start fake dns server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	normalized := make(map[string]net.IP, len(answers))
	for name, ip := range answers {
		normalized[strings.ToLower(strings.TrimSuffix(name, "."))] = ip.To4()
	}

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := answer(buf[:n], normalized); resp != nil {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()

	return conn.LocalAddr().String()
}

// Resolver returns a resolver that sends every query to the server at addr.
func Resolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func answer(query []byte, answers map[string]net.IP) []byte {
	if len(query) < 12 {
		return nil
	}

	// read the question name, ignoring any additional records such as EDNS
	var labels []string
	i := 12
	for {
		if i >= len(query) {
			return nil
		}
		l := int(query[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || i+l > len(query) {
			return nil
		}
		labels = append(labels, string(query[i:i+l]))
		i += l
	}
	if i+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[i:])
	question := query[12 : i+4]

	ip, ok := answers[strings.ToLower(strings.Join(labels, "."))]

	resp := make([]byte, 0, 12+len(question)+16)
	resp = append(resp, query[0], query[1]) // ID
	if !ok {
		resp = append(resp, 0x81, 0x83) // QR, RD, RA, NXDOMAIN
	} else {
		resp = append(resp, 0x81, 0x80) // QR, RD, RA, NOERROR
	}
	var ancount uint16
	if ok && qtype == typeA {
		ancount = 1
	}
	resp = binary.BigEndian.AppendUint16(resp, 1) // QDCOUNT
	resp = binary.BigEndian.AppendUint16(resp, ancount)
	resp = binary.BigEndian.AppendUint16(resp, 0) // NSCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0) // ARCOUNT
	resp = append(resp, question...)

	if ancount > 0 {
		resp = append(resp, 0xc0, 0x0c)                   // pointer to the question name
		resp = binary.BigEndian.AppendUint16(resp, typeA) // TYPE
		resp = binary.BigEndian.AppendUint16(resp, 1)     // CLASS IN
		resp = binary.BigEndian.AppendUint32(resp, 60)    // TTL
		resp = binary.BigEndian.AppendUint16(resp, 4)     // RDLENGTH
		resp = append(resp, ip...)
	}
	return resp
}
