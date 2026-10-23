// Command inspekt scans .eml files from the command line.
//
//	inspekt scan message.eml            human-readable report
//	inspekt scan --json a.eml b.eml     one JSON report per line (JSONL)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: inspekt scan [--json] FILE.eml [FILE.eml ...]  (use - for stdin)")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print one JSON report per line")
	_ = fs.Parse(os.Args[2:])

	eng := analyze.New(analyze.DefaultConfig)
	exit := 0
	for _, name := range fs.Args() {
		if err := scan(eng, name, *asJSON, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			exit = 1
		}
	}
	os.Exit(exit)
}

func scan(eng *analyze.Engine, name string, asJSON bool, w io.Writer) error {
	var r io.Reader = os.Stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	msg, err := email.Parse(r, email.DefaultLimits)
	if err != nil && msg == nil {
		return err
	}
	rep := eng.Analyze(msg)

	if asJSON {
		out := struct {
			File string `json:"file"`
			*analyze.Report
		}{name, rep}
		return json.NewEncoder(w).Encode(out)
	}

	fmt.Fprintf(w, "%s\n  verdict: %s (score %d)\n", name, rep.Verdict, rep.Score)
	if msg.From != nil {
		fmt.Fprintf(w, "  from:    %s\n", msg.From.Email)
	}
	fmt.Fprintf(w, "  subject: %s\n  links: %d  attachments: %d\n", msg.Subject, len(rep.Links), len(msg.Attachments))
	for _, s := range rep.Signals {
		fmt.Fprintf(w, "  [%-6s +%2d] %s: %v\n", s.Severity, s.Score, s.ID, s.Evidence)
	}
	return nil
}
