// Command rastro is the entry point of the forensic triage tool.
//
// It does one thing so far: read the Windows event logs in a directory and say
// what it found. That is deliberately little, and it is the first thing in this
// repository that can be run rather than tested — which makes it the first
// chance to check that the reader produces what the packages below it expect.
//
// Usage:
//
//	rastro read [-sample] [-codes] <directory>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/source/evtx"
	"github.com/manu222/rastro/internal/winevent"
)

const usage = `usage:
  rastro read   [-sample] [-codes] <evidence directory>
  rastro detect [-rules <directory>] [-examples <n>] <evidence directory>
  rastro report [-rules <directory>] [-format md|html|json]
                [-sections entities,timeline,tactics] [-out <file>]
                [-baseline <earlier report.json>] <evidence directory>`

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if os.Args[1] == "report" {
		if err := runReport(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "detect" {
		if err := runDetect(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] != "read" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-sample":
			sample = true
		case "-codes":
			codes = true
		default:
			fmt.Fprintf(os.Stderr, "unknown option %s\n", args[0])
			os.Exit(2)
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

var (
	sample  bool
	samples = map[string]*event.Event{}

	// codes turns on the audit of the values Windows writes as references into
	// a provider's message table. Which of them the evidence actually contains
	// is what decides how much translation is worth writing, and that is a
	// question for the corpus rather than for the catalogue.
	codes     bool
	codesSeen = map[string]*codeSighting{}
)

// noteCodes records every message-table reference in one event, with the field
// it sat on.
func noteCodes(e *event.Event) {
	for field, v := range e.Raw {
		if !winevent.IsMessageRef(v) {
			continue
		}
		if _, translated := winevent.Explain(field, v); translated {
			continue
		}
		c := codesSeen[v]
		if c == nil {
			c = &codeSighting{fields: map[string]bool{}}
			codesSeen[v] = c
		}
		c.n++
		c.fields[field] = true
	}
}

type codeSighting struct {
	n      int
	fields map[string]bool
}

// printCodes lists the message-table references in the evidence, with the
// fields they appeared on. The field name is what makes a code resolvable: the
// same number means different things under different fields, so a code without
// its field is not a translation waiting to happen, it is a guess waiting to
// happen.
func printCodes() {
	if len(codesSeen) == 0 {
		fmt.Printf("\nMessage codes   : none in this evidence\n")
		return
	}
	keys := make([]string, 0, len(codesSeen))
	for k := range codesSeen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if codesSeen[keys[i]].n != codesSeen[keys[j]].n {
			return codesSeen[keys[i]].n > codesSeen[keys[j]].n
		}
		return keys[i] < keys[j]
	})
	fmt.Printf("\nMessage codes still untranslated: %d\n", len(keys))
	for _, k := range keys {
		fields := make([]string, 0, len(codesSeen[k].fields))
		for f := range codesSeen[k].fields {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		fmt.Printf("  %-10s x%-7d %s\n", k, codesSeen[k].n, strings.Join(fields, ", "))
	}
}

// printSamples lists one record per source and event identifier, with every
// field it carries.
func printSamples() {
	keys := make([]string, 0, len(samples))
	for k := range samples {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("\nOne record of each source and event id (%d):\n", len(keys))
	for _, k := range keys {
		e := samples[k]
		fmt.Printf("\n=== %s   %s   %s\n", k, e.Host.Value, e.Time.Format("2006-01-02 15:04:05"))
		// What the mapping made of it, printed before the raw fields so that a
		// wrong actor or a missing target is visible next to the record it was
		// read from.
		meaning := e.Action
		if meaning == "" {
			meaning = "(not mapped)"
		}
		fmt.Printf("  -> %-14s %s\n", e.Class.String(), meaning)
		if e.User.Known() {
			fmt.Printf("  -> account      %s\n", e.User.Value)
		}
		if e.Process.Image.Known() {
			fmt.Printf("  -> actor        %s %s\n", e.Process.Image.Value, e.Process.CommandLine.Value)
		}
		if e.Target.Image.Known() {
			fmt.Printf("  -> target       %s\n", e.Target.Image.Value)
		}
		if e.Parent.Image.Known() {
			fmt.Printf("  -> parent       %s\n", e.Parent.Image.Value)
		}
		for _, ent := range e.Entities {
			fmt.Printf("  -> %-12s %s (%s)\n", ent.Kind.String(), ent.Field.Value, ent.Role)
		}
		names := make([]string, 0, len(e.Raw))
		for n := range e.Raw {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := e.Raw[n]
			if len(v) > 90 {
				v = v[:90] + "..."
			}
			fmt.Printf("    %-26s %s\n", n, v)
		}
	}
}

func run(dir string) error {
	root, done, err := openEvidence(dir)
	if err != nil {
		return err
	}
	defer done()
	reader := evtx.New(root)

	var (
		files         int
		records       int
		damaged       int
		unreadable    int
		withoutTime   int
		firstFailure  string
		skippedFields int
		byChannel     = map[string]int{}
		byTimeField   = map[string]int{}
		blocks        = map[string]int{}
		classified    int
		byAction      = map[string]int{}
		earliest      time.Time
		latest        time.Time
	)

	start := time.Now()
	list, _, err := evidenceFiles(root)
	if err != nil {
		return err
	}
	readOne := func(path string) error {
		if !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		files++

		stats, err := reader.ReadFile(path, func(e *event.Event) error {
			records++
			byChannel[e.Origin.Producer]++
			byTimeField[e.Origin.TimeField]++
			if e.Action != "" {
				classified++
				byAction[e.Action]++
			}
			if codes {
				noteCodes(e)
			}
			// One record of each source, kept whole. This is what the mapping
			// tables are written against: which field holds the actor, which
			// holds the target, which identifier belongs to which event. Doing
			// it from memory is how a reader ends up looking for fields that
			// are not there.
			if sample {
				// Keyed on the event id and not on Activity, which now holds
				// the provider's own word for what happened when it writes
				// one and would group two different events together.
				key := fmt.Sprintf("%s/%s", e.Origin.Producer, e.Raw["EventID"])
				if _, seen := samples[key]; !seen {
					samples[key] = e
				}
			}
			if e.Time.IsZero() {
				withoutTime++
				return nil
			}
			if earliest.IsZero() || e.Time.Before(earliest) {
				earliest = e.Time
			}
			if e.Time.After(latest) {
				latest = e.Time
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), err)
			return nil
		}
		for name, n := range stats.Blocks {
			blocks[name] += n
		}
		damaged += stats.DamagedChunks
		unreadable += stats.Unreadable
		skippedFields += stats.SkippedFields
		if stats.FirstFailure != nil && firstFailure == "" {
			firstFailure = fmt.Sprintf("%s: %v", filepath.Base(path), stats.FirstFailure)
		}
		if stats.Stopped != "" {
			fmt.Fprintf(os.Stderr, "warning: %s: stopped early, %s\n", filepath.Base(path), stats.Stopped)
		}
		return nil
	}
	for _, path := range list {
		if err := readOne(path); err != nil {
			return err
		}
	}

	fmt.Printf("Files read      : %d\n", files)
	fmt.Printf("Records         : %d\n", records)
	fmt.Printf("Elapsed         : %s\n", time.Since(start).Round(time.Millisecond))
	if records > 0 {
		fmt.Printf("Per record      : %s\n", (time.Since(start) / time.Duration(records)).Round(time.Nanosecond))
	}
	if damaged > 0 {
		fmt.Printf("Damaged chunks  : %d  (skipped; everything after them was still read)\n", damaged)
	}
	if unreadable > 0 {
		fmt.Printf("Unreadable      : %d record(s)\n", unreadable)
		fmt.Printf("  first cause   : %s\n", firstFailure)
	}
	if skippedFields > 0 {
		fmt.Printf("Skipped fields  : %d  (records kept, those fields left out)\n", skippedFields)
	}
	if withoutTime > 0 {
		fmt.Printf("Without a time  : %d record(s)\n", withoutTime)
	}
	// Which field each event's time came from. A timeline built from two
	// different meanings of "when" has to be able to say which it used where.
	// Values read from somewhere other than System and EventData. Quiet on
	// almost every record, and the two events that say the log was cleared
	// depend on it entirely.
	if len(blocks) > 0 {
		names := make([]string, 0, len(blocks))
		for name := range blocks {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("Other blocks    : %-40s %d record(s)\n", name, blocks[name])
		}
	}
	if n := byTimeField["UtcTime"]; n > 0 {
		fmt.Printf("Provider's time : %d of %d record(s) state when the event happened\n", n, records)
	}
	if !earliest.IsZero() {
		fmt.Printf("Time span       : %s to %s\n",
			earliest.Format("2006-01-02 15:04:05"), latest.Format("2006-01-02 15:04:05"))
	}

	fmt.Println("\nSources:")
	type row struct {
		name string
		n    int
	}
	rows := make([]row, 0, len(byChannel))
	for k, v := range byChannel {
		rows = append(rows, row{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	for i, r := range rows {
		if i == 12 {
			fmt.Printf("  ... and %d more\n", len(rows)-i)
			break
		}
		name := r.name
		if name == "" {
			name = "(no channel and no provider name)"
		}
		fmt.Printf("  %-55s %7d\n", name, r.n)
	}

	// The audit. Anything here is a field that arrived in a shape no table
	// declares, which means a rule that touches it may not match. Printed last
	// because it is the part worth acting on.
	// What the evidence was understood to be. A low number here is not a
	// failure - most of this corpus is RPC trace events that no table covers -
	// but it has to be visible, because "events classified" and "events read"
	// are different claims and a report must not blur them.
	fmt.Printf("\nClassified      : %d of %d record(s)\n", classified, records)
	if len(byAction) > 0 {
		rows := make([]string, 0, len(byAction))
		for a := range byAction {
			rows = append(rows, a)
		}
		sort.Slice(rows, func(i, j int) bool {
			if byAction[rows[i]] != byAction[rows[j]] {
				return byAction[rows[i]] > byAction[rows[j]]
			}
			return rows[i] < rows[j]
		})
		for _, a := range rows {
			fmt.Printf("  %-45s %7d\n", a, byAction[a])
		}
	}

	if codes {
		printCodes()
	}
	if sample {
		printSamples()
	}

	gaps := reader.Gaps()
	fmt.Printf("\nUndeclared field shapes: %d\n", len(gaps))
	for i, g := range gaps {
		if i == 20 {
			fmt.Printf("  ... and %d more\n", len(gaps)-i)
			break
		}
		fmt.Printf("  %-45s %-18s %-10s x%-6d e.g. %s\n",
			g.Producer, g.Field, g.Shape, g.Count, g.Sample)
	}
	return nil
}
