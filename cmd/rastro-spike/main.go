// Command rastro-spike is a throwaway feasibility probe.
//
// Its only purpose is to answer one question before any real work starts: can
// Go read Windows event logs reliably enough to build the Rastro engine on top?
// If this works, phase 2 of the plan is viable. If it does not, the stack needs
// rethinking before weeks are spent on it.
//
// This binary is deliberately disposable. Do not build on it.
//
// Usage:
//
//	rastro-spike <file.evtx>
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

// maxListed caps how many events are printed. The probe is meant to be read by
// a human, not to dump a whole log.
const maxListed = 10

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rastro-spike <file.evtx>")
		os.Exit(1)
	}
	path := os.Args[1]

	fd, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open %q: %v\n", path, err)
		os.Exit(1)
	}
	defer fd.Close()

	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %q does not look like a valid EVTX file: %v\n", path, err)
		os.Exit(1)
	}

	fmt.Printf("File   : %s\n", path)
	fmt.Printf("Chunks : %d\n\n", len(chunks))
	fmt.Printf("%-4s %-8s %-21s %-24s %s\n", "#", "EventID", "Timestamp (UTC)", "Computer", "Channel")
	fmt.Println("-------------------------------------------------------------------------------------------------")

	total := 0
	byID := map[int]int{}

	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			// A corrupt chunk must not abort the rest of the file. Evidence is
			// frequently damaged, and giving up on the whole log because of one
			// bad chunk would lose everything after it.
			fmt.Fprintf(os.Stderr, "warning: unreadable chunk, skipping: %v\n", err)
			continue
		}

		for _, rec := range records {
			dict, ok := rec.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}
			ev, ok := ordereddict.GetMap(dict, "Event")
			if !ok {
				continue
			}

			eventID, _ := ordereddict.GetInt(ev, "System.EventID.Value")
			channel, _ := ordereddict.GetString(ev, "System.Channel")
			computer, _ := ordereddict.GetString(ev, "System.Computer")

			// The timestamp is not a string: it is a float holding seconds since
			// the Unix epoch.
			timestamp := "-"
			if v, ok := ordereddict.GetAny(ev, "System.TimeCreated.SystemTime"); ok {
				if secs, ok := v.(float64); ok {
					timestamp = time.Unix(int64(secs), 0).UTC().Format("2006-01-02 15:04:05")
				}
			}

			total++
			byID[eventID]++

			if total <= maxListed {
				fmt.Printf("%-4d %-8d %-21s %-24s %s\n", total, eventID, timestamp, computer, channel)
			}

			// Sysmon event 10 is process access, the source for LSASS credential
			// dumping detection. It is printed in full because it exposes the
			// finding that shapes phase 2: see hex.go.
			if eventID == 10 {
				source, _ := ordereddict.GetString(ev, "EventData.SourceImage")
				target, _ := ordereddict.GetString(ev, "EventData.TargetImage")
				if raw, ok := ordereddict.GetAny(ev, "EventData.GrantedAccess"); ok {
					access, valid := toHex(raw)
					fmt.Printf("\n     >> Process access\n")
					fmt.Printf("        Source        : %s\n", source)
					fmt.Printf("        Target        : %s\n", target)
					fmt.Printf("        GrantedAccess : %-10v  (as the library returns it, type %T)\n", raw, raw)
					if valid {
						fmt.Printf("        Normalised    : %-10s  <- this is what the Sigma rule compares against\n\n", access)
					} else {
						fmt.Printf("        Normalised    : CONVERSION FAILED - check toHex()\n\n")
					}
				}
			}
		}
	}

	fmt.Printf("\nEvents read: %d\n", total)
	if len(byID) > 0 {
		fmt.Println("Breakdown by EventID:")
		for id, n := range byID {
			fmt.Printf("   EventID %-6d %d event(s)\n", id, n)
		}
	}
}
