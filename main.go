package main

import (
	"fmt"
	"net"

	"golang.org/x/net/http2"
)

// CVE-2026-33814 affects two packages: net/http in the Go standard library, and
// golang.org/x/net/http2.
//
// This branch reaches only the golang.org/x/net half. Transport.NewClientConn is
// one of the affected golang.org/x/net/http2 symbols, and it takes a plain
// net.Conn -- so net/http is never imported here and none of its affected symbols
// (Client.Do, Transport.RoundTrip, Get, Post, ...) end up in the call graph.
//
// Expected: arc:positive + arc:positive:non-stdlib, no arc:positive:stdlib, and a
// bump PR raising golang.org/x/net to v0.53.0.
func main() {
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
