package main

import (
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// CVE-2026-33814 affects two packages: net/http in the Go standard library, and
// golang.org/x/net/http2.
//
// This branch reaches both halves: http.Get is an affected net/http symbol, and
// http2.Transport.NewClientConn is an affected golang.org/x/net/http2 symbol.
//
// Expected: arc:positive + arc:positive:stdlib + arc:positive:non-stdlib, and a
// bump PR covering golang.org/x/net only. The stdlib half must not suppress
// remediation of the non-stdlib half -- that regression is the point of this
// branch.
func main() {
	resp, err := http.Get("https://example.com")
	if err != nil {
		fmt.Println("request failed:", err)
		return
	}
	resp.Body.Close()

	fmt.Println("status:", resp.Status)

	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		fmt.Println("dial failed:", err)
		return
	}
	defer conn.Close()

	tr := &http2.Transport{}

	if _, err := tr.NewClientConn(conn); err != nil {
		fmt.Println("http2 handshake failed:", err)
		return
	}

	fmt.Println("http2 client connection established")
}
