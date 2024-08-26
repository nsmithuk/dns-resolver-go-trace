package trace

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nsmithuk/dns-resolver-go/resolver"
	"github.com/nsmithuk/dns-resolver-go/resolver/dnssec"
)

func GetRecursiveQueryConsoleTree(trace *resolver.RecursiveQueryTrace) string {
	text.EnableColors()

	headerText := text.Colors{text.Bold, text.Italic, text.FgHiMagenta}
	greenText := text.Colors{text.FgGreen}
	faintText := text.Colors{text.Faint}

	//---

	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedRounded)

	var c uint8 = 0
	for _, entry := range trace.Records {
		switch r := entry.(type) {
		case resolver.RecursiveQueryTraceLookup:
			if r.Depth < c {
				for range c - r.Depth {
					l.UnIndent()
				}
				c = r.Depth
			}

			l.AppendItem(headerText.Sprint("DNS Query"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s %s", greenText.Sprint("for"), r.Domain, r.Rrtype))
			l.AppendItem(fmt.Sprintf("%s: %s %s", greenText.Sprint("on"), r.ServerHost, r.ServerUri))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("took"), r.Latency))
			l.AppendItem(fmt.Sprintf("%s: %t", greenText.Sprint("truncated"), r.Truncated))
			l.AppendItem(fmt.Sprintf("%s: %t", greenText.Sprint("authoritative"), r.Authoritative))

			if len(r.Answers) > 0 {
				l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("answers found")))
				l.Indent()
				for _, r := range r.Answers {
					l.AppendItem(faintText.Sprint(r))
				}
				l.UnIndent()
			}

			if len(r.Nameservers) > 0 {
				l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("nameservers found")))
				l.Indent()
				for _, r := range r.Nameservers {
					l.AppendItem(faintText.Sprint(r))
				}
				l.UnIndent()
			}

			if len(r.Extra) > 0 {
				l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("extra records returned")))
				l.Indent()
				for _, r := range r.Extra {
					l.AppendItem(faintText.Sprint(r))
				}
				l.UnIndent()
			}

		}
		c += 1
	}

	return l.Render()
}

func GetAuthenticationConsoleTree(trace *dnssec.Trace) string {
	text.EnableColors()

	headerText := text.Colors{text.Bold, text.Italic, text.FgHiMagenta}
	greenText := text.Colors{text.FgGreen}
	faintText := text.Colors{text.Faint}

	//---

	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedRounded)

	var lastSeenDepth uint8 = 0
	for _, entry := range trace.Records {

		switch r := entry.(type) {
		case dnssec.TraceAuthenticatingMessage:
			l.AppendItem(headerText.Sprint("DNS Message to Authenticate"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("domain"), r.Domain))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("type"), r.Rrtype))
			l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("answers")))
			l.Indent()
			for _, r := range r.Answers {
				l.AppendItem(faintText.Sprint(r))
			}
			l.UnIndent()
			l.UnIndent()
		case dnssec.TraceDnsLookup:
			l.AppendItem(headerText.Sprint("DNS Lookup"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("domain"), r.Domain))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("type"), r.Rrtype))
			l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("answers")))
			l.Indent()
			for _, r := range r.Answers {
				l.AppendItem(faintText.Sprint(r))
			}
			l.UnIndent()
			l.UnIndent()
		case dnssec.TraceSignature:
			if r.Depth < lastSeenDepth {
				// Resets the tree.
				l.UnIndentAll()
			}
			lastSeenDepth = r.Depth

			l.Indent()
			l.AppendItem(headerText.Sprint("Signature Validation"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("type"), r.KeyType))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("for"), r.Domain))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("in"), r.Zone))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("key"), r.Key))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("algorithm"), r.Algorithm))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("signature"), r.Signature))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("hash"), r.KeySha256))
			l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("records")))
			l.Indent()
			for _, r := range r.Records {
				l.AppendItem(faintText.Sprint(r))
			}
			l.UnIndent()
			l.UnIndent()
			if r.KeyType == "zsk" {
				l.UnIndent()
			}
			l.UnIndent()
		case dnssec.TraceDelegationSigner:
			l.Indent()
			l.AppendItem(headerText.Sprint("Delegation Signer Check"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("zone"), r.Zone))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("from"), r.From))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("hash"), r.Hash))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("digest"), r.Digest))
			//l.UnIndent()
			l.Indent()
		}
	}

	return l.Render()
}
