package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/correlate"
	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/report"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/source/auditd"
	"github.com/manu222/rastro/internal/source/evtx"
	"github.com/manu222/rastro/internal/source/winjson"
	"github.com/manu222/rastro/internal/source/zeek"
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
	// The two halves of the connection join, which are worth seeing next to
	// each other: a run with flows and no host connections, or the other way
	// round, is a run where the join could not have found anything, and that
	// is a property of the evidence rather than a fault.
	Flows     int
	HostConns int
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

	root, done, err := openEvidence(evidenceDir)
	if err != nil {
		return in, nil, diag, err
	}
	defer done()

	in.Directory = evidenceDir
	in.Loaded = loaded.Rules
	in.Refused = loaded.Refused

	// First pass: everything that can be an ancestor. A process creation that
	// explains an event can be in a later file, so a single pass would answer
	// "who was behind this" differently depending on the order of a directory
	// listing.
	windows := evtx.New(root)
	shipped := winjson.New(root)
	linux := auditd.New(root)
	network := zeek.New(root)
	lineage := correlate.New()
	if err := walkEvidence(root, windows, shipped, linux, network, lineage.Observe); err != nil {
		return in, nil, diag, err
	}
	diag.Processes, diag.Logons = lineage.Size()
	if lineage.LogonConflicts > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf(
			"%d logon id(s) were reused on the same host for a different account, which happens "+
				"after a reboot. The first session is the one findings are attributed to, and it may be "+
				"the wrong one: %s.", lineage.LogonConflicts, lineage.FirstLogonConflict))
	}
	diag.Flows, diag.HostConns = lineage.Flows()

	index := newRuleIndex(loaded.Rules)
	// Machines by name without case, each with the spellings it arrived in:
	// one Windows machine wrote itself as Ws01 in Security and Sysmon and as
	// WS01 in other channels of the same collection.
	hosts := map[string]map[string]int{}
	type dropped struct {
		times int
		first string
	}
	auditDropped := map[string]*dropped{}
	byRule := map[string]int{}
	var matches []report.Match

	start := time.Now()
	unjoined := 0
	var loss captureLoss
	zeekFiles := 0
	all, broken, err := evidenceFiles(root)
	if err != nil {
		return in, nil, diag, err
	}
	files := withoutDescriptions(all)
	in.Notes = append(in.Notes, collectionNotes(root, all)...)
	readOne := func(path string) error {
		kind := sourceOf(path)
		if kind == sourceNone {
			return nil
		}
		in.Files++
		if kind == sourceSensor {
			stats, err := network.ReadFile(path, func(e *event.Event) error {
				loss.add(e, relTo(root, path))
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), err)
			}
			in.UnreadableRecords += stats.Unparsed + stats.Malformed + loss.unusable
			loss.unusable = 0
			return nil
		}
		if kind == sourceZeek {
			zeekFiles++
		}

		visit := func(e *event.Event) error {
			in.Records++
			if e.Host.Known() {
				k := strings.ToLower(e.Host.Value)
				if hosts[k] == nil {
					hosts[k] = map[string]int{}
				}
				hosts[k][e.Host.Value]++
			}
			// Event 1101: the audit subsystem saying it lost events before
			// they reached the Security log.
			if e.Raw["EventID"] == "1101" && e.Raw["Provider_Name"] == "Microsoft-Windows-Eventlog" {
				d := auditDropped[e.Host.Value]
				if d == nil {
					d = &dropped{first: fmt.Sprintf("%s UTC, %s record %d",
						e.Time.UTC().Format("2006-01-02 15:04:05"), e.Origin.Path, e.Origin.Record)}
					auditDropped[e.Host.Value] = d
				}
				d.times++
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
				// The other half of the connection, when the finding is about one.
				m.Peer = lineage.Connection(e)
				// And where the acting process went, when the finding is about a
				// program rather than about one of its connections.
				m.Reach = lineage.Network(e)
				// And what the network's PE analyser read of the file, when
				// the finding is about a file that crossed the wire.
				m.Exe = lineage.Executable(e)
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
			unjoined += stats.Unjoined
			failure = stats.FirstFailure
		case sourceZeek:
			stats, err := network.ReadFile(path, visit)
			rerr = err
			in.UnreadableRecords += stats.Unparsed + stats.Malformed
			failure = stats.FirstFailure
		case sourceWinJSON:
			stats, err := shipped.ReadFile(path, visit)
			rerr = err
			// A line that is not a record, and an object that cannot be turned
			// into an event, are both evidence that was not read, which is the
			// same thing the other three readers count under their own names.
			in.UnreadableRecords += stats.Unparsed + stats.Unreadable
			in.ShippedRecords += stats.Records
			in.ClockDisagreements += stats.Disagreements
			if stats.FirstDisagreement != nil && in.FirstClockDisagreement == "" {
				in.FirstClockDisagreement = fmt.Sprintf("%s: %v", filepath.Base(path), stats.FirstDisagreement)
			}
			failure = stats.FirstFailure
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), rerr)
		}
		if failure != nil && in.FirstFailure == "" {
			in.FirstFailure = fmt.Sprintf("%s: %v", filepath.Base(path), failure)
		}
		return nil
	}
	for _, path := range files {
		if err := readOne(path); err != nil {
			return in, nil, diag, err
		}
	}
	in.Elapsed = time.Since(start)
	in.UndeclaredShapes = len(windows.Gaps())
	for _, d := range shipped.Divergences() {
		in.ShipperForms = append(in.ShipperForms, report.ShipperForm{
			Producer: d.Producer, Field: d.Field, Declared: d.Declared.String(),
			Written: d.Written, Sample: d.Sample, Count: d.Count,
		})
	}

	for _, forms := range hosts {
		// The spelling most records used; the alphabetically first on a tie.
		best := ""
		for form, n := range forms {
			if best == "" || n > forms[best] || (n == forms[best] && form < best) {
				best = form
			}
		}
		in.Hosts = append(in.Hosts, best)
	}
	sort.Strings(in.Hosts)

	var lossy []string
	for host := range auditDropped {
		lossy = append(lossy, host)
	}
	sort.Strings(lossy)
	for _, host := range lossy {
		d := auditDropped[host]
		in.Notes = append(in.Notes, fmt.Sprintf(
			"The Security log of %s says %d time(s) that audit events were dropped before being "+
				"written (event 1101), first at %s. What happened on it around those times may have "+
				"left no record, and no finding there is not the same as nothing happening.",
			orUnknown(host), d.times, d.first))
	}

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
	// have read the repository. They go first and what this run found goes
	// after: assigning them used to throw away the logon-conflict note
	// appended during the first pass.
	in.Notes = append([]string{
		"An audit record written as `unit= auditd`, with a space after the equals sign, " +
			"carries no unit field at all, so a rule looking for a stopped service cannot " +
			"see it. Three records of this corpus are written that way.",
		"Sysmon writes the values of its WMI events (19, 20, 21) with a leading space, in double " +
			"quotes, with backslashes doubled: Destination arrives as ` \"c:\\\\Windows\\\\System32\\\\cmd.exe\"`. " +
			"They are matched as written, as every other Sigma backend sees them, so a rule comparing " +
			"a plain path with endswith or equality will not fire there; contains on a fragment does.",
		"Windows' message-table codes (%%NNNN) that this tool has no source for are shown as " +
			"written rather than guessed; `rastro read -codes` lists them.",
		"Zeek counts the payload bytes each side of a connection sent, and in three of its " +
			"connection states — SHR, RSTRH and OTH — it also records that it never saw the side " +
			"that opened the connection. Where this report says a capture did not see the " +
			"outbound side, that is why, and a count of zero there would have been an absence of " +
			"observation presented as a measurement.",
		"The host and the network are joined on the five-tuple and never on time. The two " +
			"sources keep their own clocks, and evidence that has been through a log shipper can " +
			"carry a time hours or days from the one the capture used, so times in this report " +
			"order events within a source and do not date them across sources. A tuple whose client " +
			"port is below 1024, as NTP's and NetBIOS's are, repeats on every exchange and is not joined.",
	}, in.Notes...)

	// What the correlation index refused to hold. A lineage cut short by a
	// limit looks exactly like evidence that was never collected, and the
	// counter existed for this sentence without anything ever writing it.
	if lineage.Dropped > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf(
			"%d process creation(s) or logon session(s) were not indexed because the correlation "+
				"limits were reached; a lineage or an account that ends early here may end because of "+
				"that and not because the evidence stops.", lineage.Dropped))
	}
	if lineage.DroppedFlows > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf(
			"%d connection(s) were not indexed because the flow limit was reached; a host connection "+
				"reported as unseen on the wire may be one of them.", lineage.DroppedFlows))
	}
	if n := loss.note(zeekFiles); n != "" {
		in.Notes = append(in.Notes, n)
	}

	if len(broken) > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf(
			"%d link(s) in the evidence directory lead nowhere and were not read; the first is %s.",
			len(broken), relTo(root, broken[0])))
	}
	if unjoined > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf(
			"%d audit EXECVE record(s) have no SYSCALL of the same event in their file, so the "+
				"program that ran is unknown and a rule asking for Image cannot match them. "+
				"Extracts filtered by record type are written that way.", unjoined))
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
	sourceZeek
	sourceWinJSON
	// What the network sensor says about itself that bears on the evidence:
	// capture_loss.log, the share of segments it saw acknowledged and never
	// saw sent. Read for the report's limits, never matched against rules.
	sourceSensor
)

func sourceOf(path string) sourceKind {
	base := strings.ToLower(filepath.Base(path))
	// Compression is not a format. A name is stripped of it before anything
	// else looks at the name, because evidence that has been through a shipper
	// usually arrives compressed and a file called host.json.gz is a host.json.
	if stripped, ok := strings.CutSuffix(base, ".gz"); ok {
		base = stripped
	}
	switch filepath.Ext(base) {
	case ".evtx":
		return sourceEVTX
	case ".json":
		// Windows events as a log shipper writes them. The extension is all
		// there is to go on, and a .json that turns out to be something else
		// counts every line as unread rather than quietly producing nothing.
		return sourceWinJSON
	case ".log":
		// Two text formats share the extension, and which one a file is gets
		// decided by its name rather than by opening it. Zeek names its logs
		// after what they contain — conn.log, dns.log, http.log — and that is
		// also what a rule asks for in its logsource, so the name is load
		// bearing either way. Anything else called .log is read as an audit
		// log, and a file that turns out to be neither is counted as unread
		// lines rather than silently producing nothing.
		name := strings.TrimSuffix(base, ".log")
		if name == "capture_loss" {
			return sourceSensor
		}
		if zeekDiagnostics[name] {
			// Zeek's own operational logs. They say what the sensor was doing
			// rather than what happened on the wire, so they are evidence of
			// nothing — and read as an audit log, which is what happened before
			// this, every line of them is counted as evidence that could not be
			// read. A number that says ten records were missed when nothing was
			// missed is worse than no number at all.
			return sourceNone
		}
		if zeekLogs[name] {
			return sourceZeek
		}
		return sourceAuditd
	}
	return sourceNone
}

// The Zeek logs this tool knows what to do with. A name not in here is not
// refused — it is read as an audit log, which will count its lines as unread
// and say so — because guessing wrong in the quiet direction is the failure
// this project spends its time avoiding.
var zeekLogs = map[string]bool{
	"conn": true, "dns": true, "http": true, "ssl": true, "files": true,
	"smb_files": true, "smb_mapping": true, "dce_rpc": true, "kerberos": true,
	"ntlm": true, "notice": true, "weird": true, "x509": true, "rdp": true,
	"ssh": true, "smtp": true, "ftp": true, "dhcp": true, "sip": true,
	"snmp": true, "software": true, "tunnel": true, "traceroute": true,
	// What Zeek's PE analyser says about an executable it saw cross the wire:
	// its architecture, its subsystem, its sections. On the compound corpus
	// that is how the network half knows a 7 KB download was a 64-bit Windows
	// binary, which is half of the only question worth asking about it.
	"pe": true,
	// Dynamic protocol detection: a connection on which an analyser gave up,
	// which is how a protocol on an unexpected port shows. Twelve lines of it in
	// the APT29 evaluation were being read as an audit log and counted unread.
	"dpd": true,
}

// Zeek's own operational logs, which are about the sensor rather than about the
// traffic. They are skipped rather than read, because the alternative is that
// an evidence directory copied straight out of a Zeek deployment reports lines
// that could not be read when there was nothing in them to read.
var zeekDiagnostics = map[string]bool{
	"analyzer": true, "packet_filter": true, "loaded_scripts": true,
	"reporter": true, "stats": true, "cluster": true,
	"broker": true, "telemetry": true, "known_services": true,
}

func relTo(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(r)
	}
	return path
}

// captureLoss adds up what Zeek's capture_loss.log says the sensor missed. Each
// row is an interval: segments it saw acknowledged, and how many of those it
// never saw sent. The ratio is computed here from the two counts rather than
// read from percent_lost, which is the same number rounded by someone else.
type captureLoss struct {
	intervals  int
	gaps, acks int64
	worstGaps  int64
	worstAcks  int64
	worstAt    string
	unusable   int
}

func (c *captureLoss) add(e *event.Event, file string) {
	gaps, err1 := strconv.ParseInt(e.Raw["gaps"], 10, 64)
	acks, err2 := strconv.ParseInt(e.Raw["acks"], 10, 64)
	if err1 != nil || err2 != nil || gaps < 0 || acks < 0 {
		c.unusable++
		return
	}
	c.intervals++
	c.gaps += gaps
	c.acks += acks
	// gaps/acks > worstGaps/worstAcks, without dividing by zero.
	if acks > 0 && (c.worstAcks == 0 || gaps*c.worstAcks > c.worstGaps*acks) {
		c.worstGaps, c.worstAcks = gaps, acks
		c.worstAt = fmt.Sprintf("%s line %d", file, e.Origin.Record)
	}
}

// note is what the report says about the sensor. Network evidence with no
// capture_loss.log is said to be of unknown completeness rather than passed
// over, because no loss reported and no loss are different statements.
func (c *captureLoss) note(zeekFiles int) string {
	switch {
	case c.intervals == 0 && zeekFiles == 0:
		return ""
	case c.intervals == 0:
		return "The network evidence carries no capture_loss.log, so how much traffic the sensor " +
			"missed is unknown: a connection reported as unseen on the wire may have crossed it uncaptured."
	case c.gaps == 0:
		return fmt.Sprintf("The network sensor reported no capture loss in %d interval(s), %d acknowledged "+
			"segment(s) in all (capture_loss.log).", c.intervals, c.acks)
	}
	return fmt.Sprintf("The network sensor reported missing %d of %d acknowledged segment(s) over %d "+
		"interval(s) (%s); the worst interval missed %d of %d, at %s. A connection reported as unseen "+
		"on the wire may be one it missed.", c.gaps, c.acks, c.intervals, percent(c.gaps, c.acks),
		c.worstGaps, c.worstAcks, c.worstAt)
}

func percent(part, whole int64) string {
	if whole == 0 {
		return "no acknowledged segments"
	}
	return strconv.FormatFloat(100*float64(part)/float64(whole), 'f', 2, 64) + "%"
}
