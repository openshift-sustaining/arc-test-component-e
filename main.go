package main

import (
	"fmt"
	"net/http"
)

// CVE-2026-33814 affects two packages: net/http in the Go standard library, and
// golang.org/x/net/http2.
//
// This branch reaches only the standard library half. http.Get is one of the
// affected net/http symbols, and golang.org/x/net is not a dependency at all, so
// the golang.org/x/net/http2 half is unreachable.
//
// Expected: arc:positive + arc:positive:stdlib, no arc:positive:non-stdlib, and
// no bump PR -- the stdlib fix belongs to the Go Toolset maintainers.
func main() {
	resp, err := http.Get("https://example.com")
	if err != nil {
		fmt.Println("request failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("status:", resp.Status)
}
