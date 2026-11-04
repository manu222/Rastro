// Command rastro is the entry point of the forensic triage tool.
//
// It does one thing so far: read the Windows event logs in a directory and say
// what it found. That is deliberately little, and it is the first thing in this
// repository that can be run rather than tested — which makes it the first
// chance to check that the reader produces what the packages below it expect.
//
// Usage:
//
//	rastro read <directory>
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
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "read" {
		fmt.Fprintln(os.Stderr, "usage: rastro read [-sample] <directory>")
		os.Exit(2)
	}
	args := os.Args[2:]
	if args[0] == "-sample" {
		sample = true
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: rastro read [-sample] <directory>")
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
)

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

func run(root string) error {
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
		earliest      time.Time
		latest        time.Time
	)

	start := time.Now()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		files++

		stats, err := reader.ReadFile(path, func(e *event.Event) error {
			records++
			byChannel[e.Origin.Producer]++
			// One record of each source, kept whole. This is what the mapping
			// tables are written against: which field holds the actor, which
			// holds the target, which identifier belongs to which event. Doing
			// it from memory is how a reader ends up looking for fields that
			// are not there.
			if sample {
				key := fmt.Sprintf("%s/%s", e.Origin.Producer, e.Activity)
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
	})
	if err != nil {
		return err
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
