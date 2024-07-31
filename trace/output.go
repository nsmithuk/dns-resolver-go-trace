package trace

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nsmithuk/dns-lookup-go/lookup"
)

func GetConsoleTree(trace *lookup.Trace) string {
	text.EnableColors()

	headerText := text.Colors{text.Bold, text.Italic, text.FgHiMagenta}
	greenText := text.Colors{text.FgGreen}
	faintText := text.Colors{text.Faint}

	//---

	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedRounded)

	for _, entry := range trace.Records {
		switch r := entry.(type) {
		case lookup.TraceLookup:
			l.AppendItem(headerText.Sprint("DNS Lookup"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s %s", greenText.Sprint("for"), r.Rrtype, r.Domain))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("on"), r.Nameserver))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("taking"), r.Latency))
			l.AppendItem(fmt.Sprintf("%s:", greenText.Sprint("answers")))
			l.Indent()
			for _, r := range r.Answers {
				l.AppendItem(faintText.Sprint(r))
			}
			l.UnIndent()
			l.UnIndent()
		case lookup.TraceSignatureValidation:
			l.Indent()
			l.AppendItem(headerText.Sprint("Signature Validation"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("type"), r.KeyType))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("for"), r.Domain))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("in"), r.Zone))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("key"), r.Key))
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
		case lookup.TraceDelegationSignerCheck:
			l.Indent()
			l.AppendItem(headerText.Sprint("Delegation Signer Check"))
			l.Indent()
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("child"), r.Child))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("parent"), r.Parent))
			l.AppendItem(fmt.Sprintf("%s: %s", greenText.Sprint("hash"), r.Hash))
			l.UnIndent()
		}
	}

	return l.Render()
}
