// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package collect

func fqdn(hostname string) string { return fqdnFromDNS(hostname) }
