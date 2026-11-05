package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/correlate"
	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/report"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/source/auditd"
	"github.com/manu222/rastro/internal/source/evtx"
)

// analyse is the one path through the evidence, and both commands use it.
//
// Keeping it single is not tidiness. `rastro detect` prints a diagnostic view
// and `rastro report` renders a document, and if each did its own reading and
// matching they would eventually disagree about how many findings there are —
// which is the failure the report's own tests check the renderers for. One
// analysis, several ways of writing it down, all the way up.
// Diagnostics are numbers about the work rather than about the evidence: how
// many rule evaluations the index avoided, how much the ancestry index holds.
// They belong to `rastro detect`, which exists to check that the machinery is
// doing what it should, and not in the report, which is about the incident.
type Diagnostics struct {
	Evaluations int64
	Processes   int
	Logons      int
}

func analyse(rulesDir, evidenceDir string) (report.Input, []report.Match, Diagnostics, error) {
	var in report.Input
	var diag Diagnostics

	loaded, err := sigma.LoadDir(rulesDir)
	if err != nil {
		return in, nil, diag, err
	}
	if len(loaded.Rules) == 0 {
		return in, nil, diag, fmt.Errorf("no rules loaded from %s", rulesDir)
	}

	root, err := evidenceRoot(evidenceDir)
	if err != nil {
		return in, nil, diag, err
	}

	in.Directory = evidenceDir
	in.Loaded = loaded.Rules
	in.Refused = loaded.Refused

	// First pass: everything that can be an ancestor. A process creation that
	// explains an event can be in a later file, so a single pass would answer
	// "who was behind this" differently depending on the order of a directory
	// listing.
	windows := evtx.New(root)
	linux := auditd.New(root)
	lineage := correlate.New()
	if err := walkEvidence(root, windows, linux, lineage.Observe); err != nil {
		return in, nil, diag, err
	}
	diag.Processes, diag.Logons = lineage.Size()

	index := newRuleIndex(loaded.Rules)
	hosts := map[string]bool{}
	byRule := map[string]int{}
	var matches []report.Match

	start := time.Now()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		kind := sourceOf(path)
		if d.IsDir() || kind == sourceNone {
			return nil
		}
		in.Files++

		visit := func(e *event.Event) error {
			in.Records++
			if e.Host.Known() {
				hosts[e.Host.Value] = true
			}
			if !e.Time.IsZero() {
				if in.Earliest.IsZero() || e.Time.Before(in.Earliest) {
					in.Earliest = e.Time
				}
				if e.Time.After(in.Latest) {
					in.Latest = e.Time
				}
			}
			candidates := index.forEvent(e)
			diag.Evaluations += int64(len(candidates))
			for _, c := range candidates {
				if !c.Matches(e.Raw) {
					continue
				}
				byRule[c.Rule.Title]++
				m := report.Match{
					Rule:    c,
					Event:   e,
					Hits:    c.Explain(e.Raw),
					Account: lineage.Account(e),
					Unknown: lineage.Unresolved(e),
				}
				m.Lineage, m.Complete = lineage.Ancestry(e)
				m.Changes = correlate.Escalations(m.Lineage)
				m.Entry, m.EntryWho = lineage.Entry(m.Lineage)
				matches = append(matches, m)
			}
			return nil
		}

		var rerr error
		var failure error
		switch kind {
		case sourceEVTX:
			stats, err := windows.ReadFile(path, visit)
			rerr = err
			in.UnreadableRecords += stats.Unreadable
			in.DamagedChunks += stats.DamagedChunks
			in.SkippedFields += stats.SkippedFields
			failure = stats.FirstFailure
		case sourceAuditd:
			stats, err := linux.ReadFile(path, visit)
			rerr = err
			// A line that is not an audit record is evidence that was not
			// read, which is the same thing a record that would not parse is
			// on the Windows side, so it is counted the same way.
			in.UnreadableRecords += stats.Unparsed
			failure = stats.FirstFailure
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), rerr)
		}
		if failure != nil && in.FirstFailure == "" {
			in.FirstFailure = fmt.Sprintf("%s: %v", filepath.Base(path), failure)
		}
		return nil
	})
	if err != nil {
		return in, nil, diag, err
	}
	in.Elapsed = time.Since(start)
	in.UndeclaredShapes = len(windows.Gaps())

	for host := range hosts {
		in.Hosts = append(in.Hosts, host)
	}
	sort.Strings(in.Hosts)

	// Rules that loaded and never fired. Over evidence chosen to exercise them
	// that is worth knowing: it is either a technique absent from this evidence
	// or a rule that cannot fire anywhere.
	for _, c := range loaded.Rules {
		if byRule[c.Rule.Title] == 0 {
			in.Silent = append(in.Silent, c.Rule.Title)
		}
	}
	sort.Strings(in.Silent)

	// The blind spots that are properties of the method rather than of this
	// run. They belong in every report, because a reader cannot be expected to
	// have read the repository.
	in.Notes = []string{
		"An audit record written as `unit= auditd`, with a space after the equals sign, " +
			"carries no unit field at all, so a rule looking for a stopped service cannot " +
			"see it. Three records of this corpus are written that way.",
		"Sysmon writes its WMI events with the values quoted and the backslashes doubled, " +
			"so a rule matching a plain path against a Sysmon 19, 20 or 21 will not fire.",
		"Ten of Windows' message-table codes are shown as written rather than translated, " +
			"because they have not been resolved against a real installation yet.",
		"There is no reader for Linux audit logs yet, so rules written against auditd " +
			"load, run and report nothing.",
	}

	return in, matches, diag, nil
}

// Which reader a file needs. Decided by extension, because the alternative is
// opening every file in an evidence directory to find out, and an evidence
// directory can hold a great many files that are neither.
type sourceKind int

const (
	sourceNone sourceKind = iota
	sourceEVTX
	sourceAuditd
)

func sourceOf(path string) sourceKind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".evtx":
		return sourceEVTX
	case ".log":
		// An audit log by convention rather than by format. A .log that turns
		// out to hold something else is counted as unread lines rather than
		// silently producing nothing, which is why the reader counts them.
		return sourceAuditd
	}
	return sourceNone
}
