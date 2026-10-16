package utils

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
)

type DNSBL struct {
	target   string
	resolver *net.Resolver
}

func NewDNSBL(target string, resolver *net.Resolver) *DNSBL {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &DNSBL{
		target:   target,
		resolver: resolver,
	}
}

var nibbleTable = [16]byte{
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'a', 'b',
	'c', 'd', 'e', 'f',
}

type DNSBLResponse uint8

func (r DNSBLResponse) Bad() bool {
	return r != ResponseGood && r != ResponseUnknown
}

const (
	ResponseGood    = DNSBLResponse(0)
	ResponseUnknown = DNSBLResponse(255)
)

func (bl DNSBL) Lookup(ctx context.Context, ip net.IP) (DNSBLResponse, error) {
	var target []byte
	if ip4 := ip.To4(); ip4 != nil {
		// max length preallocate
		target = make([]byte, 0, len(bl.target)+1+len(ip4)*4)

		for _, i := range slices.Backward(ip4) {
			target = strconv.AppendUint(target, uint64(i), 10)
			target = append(target, '.')
		}
	} else {
		// IPv6
		// max length preallocate
		target = make([]byte, 0, len(bl.target)+1+len(ip)*4)

		for _, i := range slices.Backward(ip) {
			target = append(target, nibbleTable[i&0xf], '.', nibbleTable[i>>4], '.')
		}
	}

	target = append(target, bl.target...)

	ips, err := bl.resolver.LookupIP(ctx, "ip4", string(target))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// not listed on the blocklist
			return ResponseGood, nil
		}
		return ResponseUnknown, err
	}

	for _, ip := range ips {
		ip4 := ip.To4()
		return DNSBLResponse(ip4[len(ip4)-1]), nil
	}

	return ResponseUnknown, nil
}
