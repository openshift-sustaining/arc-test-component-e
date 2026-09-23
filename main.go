package main

import (
	"fmt"

	"golang.org/x/net/dns/dnsmessage"
)

// CVE-2026-46600 affects two packages: net in the Go standard library, and
// golang.org/x/net/dns/dnsmessage.
//
// This branch reaches only the golang.org/x/net half. Message.Unpack and
// Parser.Answer are both affected dnsmessage symbols, and dnsmessage imports
// nothing but "errors" -- so net is never in the build at all, let alone its
// affected symbols (LookupCNAME, Resolver.LookupCNAME, cgoResSearch).
//
// Expected: arc:positive + arc:positive:non-stdlib, no arc:positive:stdlib, and a
// bump PR raising golang.org/x/net to v0.56.0.
func main() {
	wire, err := buildResponse()
	if err != nil {
		fmt.Println("build failed:", err)
		return
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(wire); err != nil {
		fmt.Println("unpack failed:", err)
		return
	}
	fmt.Println("unpacked answers:", len(msg.Answers))

	var parser dnsmessage.Parser
	if _, err := parser.Start(wire); err != nil {
		fmt.Println("parser start failed:", err)
		return
	}
	if err := parser.SkipAllQuestions(); err != nil {
		fmt.Println("skip questions failed:", err)
		return
	}

	for {
		answer, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			fmt.Println("parse answer failed:", err)
			return
		}
		fmt.Println("answer:", answer.Header.Name.String())
	}
}

// buildResponse packs a minimal DNS response so that main has something valid to
// feed back through the affected parsing symbols.
func buildResponse() ([]byte, error) {
	name := dnsmessage.MustNewName("www.example.com.")

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	header := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300}
	if err := builder.AResource(header, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
		return nil, err
	}

	return builder.Finish()
}
