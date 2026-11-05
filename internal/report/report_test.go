package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/manu222/rastro/internal/correlate"
	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
)

// The report has one job that matters more than looking right: it must never
// say something the analysis does not know, and it must always say what the
// analysis could not do. These tests are mostly about the second half, because
// the first is easy to get right and the second is easy to quietly drop.

func rule(title, id, level string, tags ...string) *sigma.Compiled {
	return &sigma.Compiled{Rule: &sigma.Rule{Title: title, ID: id, Level: level, Tags: tags}}
}

func sampleInput() Input {
	return Input{
		Directory:         "datasets",
		Files:             132,
		Records:           31243,
		Earliest:          time.Date(2019, 3, 25, 9, 0, 0, 0, time.UTC),
		Latest:            time.Date(2020, 9, 27, 13, 0, 0, 0, time.UTC),
		Hosts:             []string{"DC1.insecurebank.local", "IEWIN7"},
		Elapsed:           time.Second,
		Loaded:            []*sigma.Compiled{rule("A", "1", "high"), rule("B", "2", "medium")},
		Silent:            []string{"Security Service Stopped"},
		UnreadableRecords: 0,
		UndeclaredShapes:  63,
		Refused: []*sigma.Unsupported{
			{Title: "Some Correlation Rule", Feature: sigma.FeatureCorrelation,
				Reason: "describes a correlation between rules, which this engine does not evaluate"},
		},
		Notes: []string{"Sysmon writes its WMI events with the values quoted and the backslashes doubled."},
	}
}

func sampleMatch() Match {
	e := &event.Event{
		Time:     time.Date(2019, 4, 18, 16, 58, 14, 0, time.UTC),
		Class:    event.ClassProcess,
		Action:   "process opened another process",
		Activity: "10",
		Origin:   event.Origin{Path: "Credential Access/mimikatz.evtx", Record: 22, Producer: "Microsoft-Windows-Sysmon/Operational"},
		Host:     event.Seen("IEWIN7"),
		Process:  event.Process{Image: event.Seen(`C:\powershell.exe`), GUID: event.Seen("GUID-PS")},
		Target:   event.Process{Image: event.Seen(`C:\Windows\system32\lsass.exe`)},
		Raw:      event.Fields{"EventID": "10", "GrantedAccess": "0x1010"},
	}
	e.Add(event.KindHost, "", e.Host)
	e.Add(event.KindFile, "target image", event.Seen(`C:\Windows\system32\lsass.exe`))

	return Match{
		Rule:  rule("LSASS Memory Access With Read Rights", "abc", "high", "attack.credential_access", "attack.t1003.001"),
		Event: e,
		Hits: []sigma.Hit{
			{Selection: "selection", Field: "GrantedAccess", Value: "0x1010", Pattern: "*0x1010*"},
			{Selection: "selection", Field: "TargetImage", Value: `C:\Windows\system32\lsass.exe`, Pattern: `*\lsass.exe`},
		},
		Account: event.Deduced(`IEWIN7\IEUser`, "the account the acting process was created as, from record 13 of Credential Access/mimikatz.evtx"),
		Lineage: []correlate.Step{
			{Process: &correlate.Process{
				Image: `C:\powershell.exe`, User: `IEWIN7\IEUser`, Integrity: "High",
				Origin: event.Origin{Path: "Credential Access/mimikatz.evtx", Record: 13},
			}},
		},
		Complete: false,
	}
}

func TestTheSummaryCountsWhatWasLookedAtAndWhatWasFound(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})

	if r.Evidence.Records != 31243 || r.Evidence.Files != 132 {
		t.Errorf("evidence: %+v", r.Evidence)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings: %d", len(r.Findings))
	}
	if len(r.Severity) != 1 || r.Severity[0].Level != "high" {
		t.Errorf("severity: %+v", r.Severity)
	}
}

// A deduced value has to stay marked all the way to the page. This is the one
// property that cannot be allowed to be lost in a renderer.
func TestADeducedAccountIsMarkedInEveryRendering(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})
	f := r.Findings[0]
	if !f.AccountDeduced {
		t.Fatal("the account was recorded as observed")
	}
	if f.AccountWhy == "" {
		t.Fatal("the deduction carries no reasoning")
	}

	var md, html, js strings.Builder
	if err := Markdown(&md, r, AllSections); err != nil {
		t.Fatal(err)
	}
	if err := HTML(&html, r, AllSections); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, r); err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{"markdown": md.String(), "html": html.String()} {
		if !strings.Contains(out, "deduced") {
			t.Errorf("%s: a deduced account is presented as if it had been recorded", name)
		}
		if !strings.Contains(out, "record 13") {
			t.Errorf("%s: the deduction does not say which record it came from", name)
		}
	}
	var decoded Report
	if err := json.Unmarshal([]byte(js.String()), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Findings[0].AccountDeduced {
		t.Error("json: the deduced flag did not survive the round trip")
	}
}

// Whichever views were asked for, the limits are always there. A reader who
// asked for the timeline alone still has to be told what did not run.
func TestTheLimitsAreInEveryRenderingAndEverySelectionOfViews(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})

	for _, sections := range []Section{
		SectionEntities, SectionTimeline, SectionTactics,
		SectionEntities | SectionTimeline, AllSections,
	} {
		var md, html strings.Builder
		if err := Markdown(&md, r, sections); err != nil {
			t.Fatal(err)
		}
		if err := HTML(&html, r, sections); err != nil {
			t.Fatal(err)
		}
		for name, out := range map[string]string{"markdown": md.String(), "html": html.String()} {
			if !strings.Contains(out, "could not do") {
				t.Errorf("%s with sections %d: the limits section is missing", name, sections)
			}
			if !strings.Contains(out, "Some Correlation Rule") {
				t.Errorf("%s with sections %d: a refused rule is not reported", name, sections)
			}
			if !strings.Contains(out, "Security Service Stopped") {
				t.Errorf("%s with sections %d: a rule that ran and found nothing is not reported", name, sections)
			}
		}
	}
}

func TestSectionsSelectWhatIsRendered(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})

	cases := []struct {
		sections Section
		wants    []string
		missing  []string
	}{
		{SectionEntities, []string{"What is affected"}, []string{"How it unfolded", "What the attacker was doing"}},
		{SectionTimeline, []string{"How it unfolded"}, []string{"What is affected", "What the attacker was doing"}},
		{SectionTactics, []string{"What the attacker was doing"}, []string{"What is affected", "How it unfolded"}},
		{SectionEntities | SectionTactics, []string{"What is affected", "What the attacker was doing"}, []string{"How it unfolded"}},
		{AllSections, []string{"What is affected", "How it unfolded", "What the attacker was doing"}, nil},
	}
	for _, c := range cases {
		var md strings.Builder
		if err := Markdown(&md, r, c.sections); err != nil {
			t.Fatal(err)
		}
		for _, want := range c.wants {
			if !strings.Contains(md.String(), want) {
				t.Errorf("sections %d: %q is missing", c.sections, want)
			}
		}
		for _, gone := range c.missing {
			if strings.Contains(md.String(), gone) {
				t.Errorf("sections %d: %q should not be there", c.sections, gone)
			}
		}
	}
}

// The entity view is what someone reads to decide what to isolate, so the worst
// thing has to be at the top.
func TestEntitiesAreOrderedBySeverity(t *testing.T) {
	low := sampleMatch()
	low.Rule = rule("Something Minor", "x", "low")
	low.Event = &event.Event{
		Time: time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
		Host: event.Seen("QUIET-PC"),
		Raw:  event.Fields{},
	}
	low.Event.Add(event.KindHost, "", low.Event.Host)
	low.Account = event.Field{}
	low.Lineage = nil

	r := Build(sampleInput(), []Match{low, sampleMatch()})
	if len(r.Entities) == 0 {
		t.Fatal("no entities")
	}
	if r.Entities[0].Worst != "high" {
		t.Errorf("the worst entity is not first: %+v", r.Entities)
	}
	// And every entity of the quieter finding is still there.
	var found bool
	for _, e := range r.Entities {
		if e.Name == "QUIET-PC" {
			found = true
			if e.Worst != "low" {
				t.Errorf("QUIET-PC: %+v", e)
			}
		}
	}
	if !found {
		t.Error("a host with only a low finding was dropped from the view")
	}
}

// A rule with no ATT&CK tag must not vanish from the tactic view, because a
// reader counting findings across views would then be short by one and have no
// way to know.
func TestAnUntaggedRuleStillAppearsInTheTacticView(t *testing.T) {
	m := sampleMatch()
	m.Rule = rule("Untagged Rule", "y", "high")

	r := Build(sampleInput(), []Match{m})
	total := 0
	for _, t := range r.Tactics {
		total += t.Findings
	}
	if total != len(r.Findings) {
		t.Errorf("the tactic view accounts for %d of %d findings", total, len(r.Findings))
	}
	if r.Tactics[0].Name != "untagged" {
		t.Errorf("tactics: %+v", r.Tactics)
	}
}

// ATT&CK tags are one namespace and which half a tag belongs to is decided by
// its shape. Getting it wrong would file a tactic as a technique.
func TestTagsAreSplitIntoTacticsAndTechniques(t *testing.T) {
	tactics, techniques := attack([]string{
		"attack.credential_access", "attack.t1003.001", "attack.privilege_escalation",
		"attack.t1546.008", "cve.2021.1234", "detection.threat_hunting",
	})
	if len(tactics) != 2 || tactics[0] != "credential access" {
		t.Errorf("tactics: %v", tactics)
	}
	if len(techniques) != 2 || techniques[0] != "T1003.001" {
		t.Errorf("techniques: %v", techniques)
	}
}

// An incomplete chain says so. The alternative is a reader believing the chain
// reached the beginning.
func TestAnIncompleteChainIsReportedAsIncomplete(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})
	if r.Limits.IncompleteChains != 1 {
		t.Errorf("incomplete chains: %d", r.Limits.IncompleteChains)
	}
	var md strings.Builder
	if err := Markdown(&md, r, AllSections); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "the chain stops here") {
		t.Error("the report does not say the chain is short")
	}
}

// The report describes attacker-chosen input, so a command line containing a
// script tag must not come out of the HTML as a script tag.
func TestTheHTMLEscapesWhatItDescribes(t *testing.T) {
	m := sampleMatch()
	m.Hits = []sigma.Hit{{
		Selection: "selection", Field: "CommandLine",
		Value:   `powershell -c "<script>alert(1)</script>"`,
		Pattern: "*powershell*",
	}}

	r := Build(sampleInput(), []Match{m})
	var html strings.Builder
	if err := HTML(&html, r, AllSections); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html.String(), "<script>alert(1)</script>") {
		t.Fatal("a report of a malicious command line executed it")
	}
	if !strings.Contains(html.String(), "alert(1)") {
		t.Error("the value was not shown at all, which hides the evidence instead of escaping it")
	}
}

func TestParseSections(t *testing.T) {
	for in, want := range map[string]Section{
		"":                          AllSections,
		"all":                       AllSections,
		"entities":                  SectionEntities,
		"timeline":                  SectionTimeline,
		"tactics":                   SectionTactics,
		"entities,tactics":          SectionEntities | SectionTactics,
		" timeline , entities ":     SectionTimeline | SectionEntities,
		"entities,timeline,tactics": AllSections,
	} {
		got, err := ParseSections(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: want %d, got %d", in, want, got)
		}
	}
	if _, err := ParseSections("nonsense"); err == nil {
		t.Error("an unknown section was accepted")
	}
}

// Both renderings describe the same analysis, so neither may know something the
// other does not. The figures are what this checks, because a renderer that
// starts calculating is how two reports of one analysis stop agreeing.
func TestTheRenderingsAgreeOnTheFigures(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})
	var md, html strings.Builder
	if err := Markdown(&md, r, AllSections); err != nil {
		t.Fatal(err)
	}
	if err := HTML(&html, r, AllSections); err != nil {
		t.Fatal(err)
	}
	for _, figure := range []string{"31243", "132", "63"} {
		if !strings.Contains(md.String(), figure) {
			t.Errorf("markdown is missing the figure %s", figure)
		}
		if !strings.Contains(html.String(), figure) {
			t.Errorf("html is missing the figure %s", figure)
		}
	}
}

// The report listed insecurebank\Administrator and insecurebank\administrator
// as two accounts with four findings and one. They are one account: Windows
// does not distinguish the case of a name. Splitting them understates both and
// invites the reader to believe there were two.
func TestTwoSpellingsOfOneAccountAreOneEntity(t *testing.T) {
	upper := sampleMatch()
	upper.Account = event.Seen(`insecurebank\Administrator`)
	lower := sampleMatch()
	lower.Account = event.Seen(`insecurebank\administrator`)

	r := Build(sampleInput(), []Match{upper, lower})
	accounts := 0
	for _, e := range r.Entities {
		if e.Kind == "account" {
			accounts++
			if e.Findings != 2 {
				t.Errorf("the two findings were not counted on one account: %+v", e)
			}
		}
	}
	if accounts != 1 {
		t.Errorf("want one account entity, got %d: %+v", accounts, r.Entities)
	}
}

// A path keeps its case, because Windows does not distinguish it and Linux
// does, and there is no reader for Linux evidence yet to say which rule
// applies. The consequence is visible rather than silent.
func TestPathsAreNotMergedByCase(t *testing.T) {
	a := sampleMatch()
	a.Event.Entities = nil
	a.Event.Add(event.KindFile, "image", event.Seen(`C:\Windows\System32\cmd.exe`))
	b := sampleMatch()
	b.Event = &event.Event{Time: a.Event.Time, Host: event.Seen("IEWIN7"), Raw: event.Fields{}}
	b.Event.Add(event.KindFile, "image", event.Seen(`c:\windows\system32\cmd.exe`))

	r := Build(sampleInput(), []Match{a, b})
	files := 0
	for _, e := range r.Entities {
		if e.Kind == "file" {
			files++
		}
	}
	if files != 2 {
		t.Errorf("want two file entities until a source says which comparison applies, got %d", files)
	}
}

// A logon session ties events together and is not a thing anybody isolates, so
// it belongs on the finding and not in the list of what is affected.
func TestSessionsAreNotListedAsAffectedThings(t *testing.T) {
	m := sampleMatch()
	m.Event.Add(event.KindSession, "actor", event.Seen("999"))

	r := Build(sampleInput(), []Match{m})
	for _, e := range r.Entities {
		if e.Kind == "session" {
			t.Errorf("a session is in the list of affected things: %+v", e)
		}
	}
	// And it is still on the finding, where it is useful.
	var found bool
	for _, inv := range r.Findings[0].Involved {
		if inv.Kind == "session" {
			found = true
		}
	}
	if !found {
		t.Error("the session was dropped from the finding as well")
	}
}

// Zeek counts the payload bytes each side sent, and in three of its connection
// states it also records that it never saw the side that opened the
// connection. A report that turns that into "0 bytes out" is stating a
// measurement the evidence does not contain — and it is not an edge case:
// 2,660 of the 2,711 flows in the compound corpus are in one of those states.
func TestACaptureThatMissedOneDirectionDoesNotReportZeroBytes(t *testing.T) {
	m := sampleMatch()
	m.Peer = correlate.Connection{
		Flow: &correlate.Flow{
			UID: "CwSLisOv4lXMZlXd3", State: "SHR",
			Sent: "0", Received: "7373",
			Origin: event.Origin{Path: "conn.log", Record: 9},
		},
		Why: "the only flow in this evidence for 192.168.1.41:51126 to 10.0.5.13:80 over tcp",
	}
	r := Build(sampleInput(), []Match{m})

	o := r.Findings[0].Other
	if o == nil {
		t.Fatal("the flow did not reach the report")
	}
	if o.OutboundSeen {
		t.Error("a flow in state SHR was reported as having its outbound side observed")
	}
	if o.Sent != "" {
		t.Errorf("a count of %q was kept for a direction the capture did not see", o.Sent)
	}
	if o.Received != "7373" {
		t.Errorf("the direction that was seen was lost: %q", o.Received)
	}

	for _, out := range []string{render(t, Markdown, r), render(t, HTML, r)} {
		if strings.Contains(out, "0 bytes out") {
			t.Error("a rendering claims zero bytes out on a connection whose outbound side was never captured")
		}
		if !strings.Contains(out, "did not see the side that opened it") {
			t.Error("a rendering shows the flow without saying one direction is missing")
		}
	}
}

// And a flow Zeek did see both ends of keeps its numbers, or the caveat above
// would be quietly swallowing real measurements.
func TestAFullyObservedFlowKeepsBothCounts(t *testing.T) {
	m := sampleMatch()
	m.Peer = correlate.Connection{
		Flow: &correlate.Flow{
			UID: "Cfull", State: "SF", Sent: "77", Received: "295",
			Origin: event.Origin{Path: "conn.log", Record: 3},
		},
		Why: "the only flow in this evidence for it",
	}
	r := Build(sampleInput(), []Match{m})

	o := r.Findings[0].Other
	if !o.OutboundSeen || o.Sent != "77" || o.Received != "295" {
		t.Errorf("a normally terminated flow lost a count: %+v", o)
	}
	if !strings.Contains(render(t, Markdown, r), "77 bytes out and 295 back") {
		t.Error("the markdown rendering dropped the counts")
	}
}

// Where a process went is shown with a cap and a total, because a service
// process opens hundreds and a report nobody finishes reading is worse than a
// short one. The total is what says how much was left out.
func TestWhereAProcessWentIsCappedButTheTotalIsNot(t *testing.T) {
	m := sampleMatch()
	m.Reach = correlate.Reach{Total: 9, OnWire: 1}
	for i := 0; i < 9; i++ {
		m.Reach.Sightings = append(m.Reach.Sightings, correlate.Sighting{
			Remote: "10.0.5.13:8080", Protocol: "tcp",
			Origin: event.Origin{Path: "host.json.gz", Record: int64(100 + i)},
		})
	}
	m.Reach.Sightings[0].Flow = &correlate.Flow{UID: "Cone", State: "SHR", Sent: "0", Received: "204532"}

	r := Build(sampleInput(), []Match{m})
	n := r.Findings[0].Network
	if n == nil {
		t.Fatal("the connections did not reach the report")
	}
	if n.Opened != 9 || n.SeenOnWire != 1 {
		t.Errorf("totals: %+v", n)
	}
	if len(n.Connections) != shownConnections {
		t.Errorf("want %d shown, got %d", shownConnections, len(n.Connections))
	}
	md := render(t, Markdown, r)
	if !strings.Contains(md, "opened 9 connections") {
		t.Error("the rendering does not say how many there were")
	}
	if !strings.Contains(md, "and 4 more") {
		t.Error("the rendering does not say how many it left out")
	}
}

// A finding about a process that touched nothing on the network gets no
// section at all. Most findings are not about a program that opened a socket,
// and a line saying so on every one of them is noise that trains a reader to
// skip the part that matters.
func TestAProcessThatOpenedNothingGetsNoNetworkSection(t *testing.T) {
	r := Build(sampleInput(), []Match{sampleMatch()})
	if n := r.Findings[0].Network; n != nil {
		t.Errorf("an empty network section was rendered: %+v", n)
	}
}

// render runs one of the renderers and returns what it wrote.
func render(t *testing.T, fn func(io.Writer, *Report, Section) error, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf, r, AllSections); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
