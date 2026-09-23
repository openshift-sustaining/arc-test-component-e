package main

import (
	"fmt"
	"net"
)

// CVE-2026-46600 affects two packages: net in the Go standard library, and
// golang.org/x/net/dns/dnsmessage.
//
// This branch reaches only the standard library half. net.LookupCNAME is one of
// the affected net symbols, and golang.org/x/net is not a dependency at all, so
// the golang.org/x/net/dns/dnsmessage half is unreachable. The copy of
// dnsmessage that net resolves with is vendored into the standard library under
// the separate vendor/golang.org/x/net/dns/dnsmessage import path, so it does
// not leak into the non-stdlib half either.
//
// Expected: arc:positive + arc:positive:stdlib, no arc:positive:non-stdlib, and
// no bump PR -- the stdlib fix belongs to the Go Toolset maintainers.
func main() {
	cname, err := net.LookupCNAME("www.example.com")
	if err != nil {
		fmt.Println("lookup failed:", err)
		return
	}

	fmt.Println("cname:", cname)
}
