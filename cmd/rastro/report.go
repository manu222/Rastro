package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/manu222/rastro/internal/report"
)

// runReport parses the arguments of the report command and writes the document.
//
// Three renderings exist because where the analyst is sitting decides which one
// is useful, and that is not something a tool gets to decide for them. A
// terminal over SSH on a server with no desktop wants Markdown. A laptop wants
// the HTML, which is self-contained and so survives being emailed. A pipeline
// wants the JSON. The three are written from one structure, so none of them can
// say something the others cannot.
func runReport(args []string) error {
	var (
		rulesDir = "rules"
		format   = ""
		sections = ""
		out      = ""
	)
	for len(args) > 1 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-rules":
			rulesDir, args = args[1], args[2:]
		case "-format":
			format, args = args[1], args[2:]
		case "-sections":
			sections, args = args[1], args[2:]
		case "-out":
			out, args = args[1], args[2:]
		default:
			return fmt.Errorf("unknown option %s", args[0])
		}
	}
	if len(args) != 1 {
		return fmt.Errorf("report wants one evidence directory")
	}

	which, err := report.ParseSections(sections)
	if err != nil {
		return err
	}

	// The format follows the file name when one is given, because a report
	// written to report.html and rendered as Markdown is a mistake nobody
	// notices until they open it. An explicit -format wins.
	if format == "" {
		switch strings.ToLower(filepath.Ext(out)) {
		case ".html", ".htm":
			format = "html"
		case ".json":
			format = "json"
		default:
			format = "md"
		}
	}

	in, matches, _, err := analyse(rulesDir, args[0])
	if err != nil {
		return err
	}
	r := report.Build(in, matches)

	w := io.Writer(os.Stdout)
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(format) {
	case "md", "markdown":
		err = report.Markdown(w, r, which)
	case "html", "htm":
		err = report.HTML(w, r, which)
	case "json":
		err = report.JSON(w, r)
	default:
		return fmt.Errorf("unknown format %q; the renderings are md, html and json", format)
	}
	if err != nil {
		return err
	}

	if out != "" {
		// Said on standard error so that it does not land in the document when
		// somebody pipes the output.
		fmt.Fprintf(os.Stderr, "%d finding(s) over %d record(s) written to %s\n",
			len(r.Findings), r.Evidence.Records, out)
	}
	return nil
}
