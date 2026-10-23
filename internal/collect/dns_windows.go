// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package collect

import (
	"context"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DNSServers lists the resolvers of the network adapters that are up (M39),
// from GetAdaptersAddresses — the same list `ipconfig /all` shows.
func DNSServers(_ context.Context) (servers []string, found bool, err error) {
	size := uint32(15 * 1024)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err != windows.ERROR_BUFFER_OVERFLOW {
			break
		}
	}
	if err != nil {
		return nil, true, err
	}
	var candidates []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if addr, ok := sockaddrIP(d.Address); ok {
				candidates = append(candidates, addr.String())
			}
		}
	}
	return usableResolvers(candidates), true, nil
}

func sockaddrIP(s windows.SocketAddress) (netip.Addr, bool) {
	if s.Sockaddr == nil {
		return netip.Addr{}, false
	}
	switch s.Sockaddr.Addr.Family {
	case windows.AF_INET:
		sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(s.Sockaddr))
		return netip.AddrFrom4(sa.Addr), true
	case windows.AF_INET6:
		sa := (*windows.RawSockaddrInet6)(unsafe.Pointer(s.Sockaddr))
		return netip.AddrFrom16(sa.Addr), true
	}
	return netip.Addr{}, false
}
