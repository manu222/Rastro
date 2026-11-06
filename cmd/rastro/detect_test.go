package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/winevent"
)

// The index exists to stop a record meeting rules that cannot match it, and the
// only way it can be wrong is by stopping a record meeting a rule that could.
// That failure is silent — the rule simply never fires — so it gets tests of
// its own.

func compile(t *testing.T, body string) *sigma.Compiled {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sigma.LoadFile(path)
	if err != nil {
		t.Fatalf("rule did not load: %v", err)
	}
	return c
}

func TestARuleIsFiledUnderTheIdentifierItNeeds(t *testing.T) {
	// The shape every rule in this repository uses: one selection pins the
	// event, another describes the behaviour. One is enough.
	c := compile(t, `
title: Pinned
logsource:
    product: windows
detection:
    process_creation:
        EventID: 1
        Channel: 'Microsoft-Windows-Sysmon/Operational'
    selection:
        Image|endswith: '\rundll32.exe'
    filter_main_known:
        CommandLine|contains: 'DllRegisterServer'
    condition: process_creation and selection and not 1 of filter_main_*
level: high
`)
	ids := requiredEventIDs(c)
	if len(ids) != 1 || ids[0] != "1" {
		t.Fatalf("want the rule filed under event 1, got %v", ids)
	}
}

// A rule whose identifier sits behind an or is not restricted by it, and has to
// keep its place in the list that sees every record.
func TestARuleWithTheIdentifierBehindAnOrIsNotIndexed(t *testing.T) {
	c := compile(t, `
title: Either log
logsource:
    product: windows
detection:
    security_log:
        Channel: 'Security'
        EventID: 1102
    system_log:
        Channel: 'System'
        EventID: 104
    condition: security_log or system_log
level: high
`)
	if ids := requiredEventIDs(c); ids != nil {
		t.Errorf("a rule behind an or was indexed under %v, and would stop being asked about half its records", ids)
	}
}

// A selection written as a list of shapes only restricts the record when every
// shape restricts it.
func TestASelectionWithAnUnpinnedShapeIsNotIndexed(t *testing.T) {
	c := compile(t, `
title: Mixed shapes
logsource:
    product: windows
detection:
    selection:
        - EventID: 1
          Image|endswith: '\cmd.exe'
        - Image|endswith: '\powershell.exe'
    condition: selection
level: low
`)
	if ids := requiredEventIDs(c); ids != nil {
		t.Errorf("indexed under %v, but the second shape matches any event id", ids)
	}
}

// Several identifiers in one selection are alternatives, so the rule belongs
// under each of them.
func TestARuleAcceptingSeveralIdentifiersIsFiledUnderEach(t *testing.T) {
	c := compile(t, `
title: Either event
logsource:
    product: windows
detection:
    selection:
        EventID:
            - 12
            - 13
            - 14
    condition: selection
level: low
`)
	ids := requiredEventIDs(c)
	if len(ids) != 3 {
		t.Fatalf("want three identifiers, got %v", ids)
	}
}

// The whole point, end to end: a record only meets the rules that could match
// it, and it meets every one of those.
func TestTheIndexNarrowsWithoutHidingAnything(t *testing.T) {
	pinned := compile(t, `
title: Only event 1
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: low
`)
	other := compile(t, `
title: Only event 10
logsource:
    product: windows
detection:
    selection:
        EventID: 10
    condition: selection
level: low
`)
	always := compile(t, `
title: Any event
logsource:
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: low
`)

	idx := newRuleIndex([]*sigma.Compiled{pinned, other, always})

	one := &event.Event{
		Origin: event.Origin{Product: "windows", Service: "sysmon"},
		Raw:    event.Fields{"EventID": "1", "Image": `C:\Windows\cmd.exe`},
	}
	got := titles(idx.forEvent(one))
	if !has(got, "Only event 1") || !has(got, "Any event") {
		t.Errorf("a record of event 1 did not meet the rules it should: %v", got)
	}
	if has(got, "Only event 10") {
		t.Errorf("a record of event 1 met a rule that needs event 10: %v", got)
	}

	// A record of an event no rule names still meets the unpinned ones, which
	// is what keeps the index from hiding anything.
	rpc := &event.Event{
		Origin: event.Origin{Product: "windows", Service: "rpc"},
		Raw:    event.Fields{"EventID": "0"},
	}
	got = titles(idx.forEvent(rpc))
	if len(got) != 1 || got[0] != "Any event" {
		t.Errorf("want only the unpinned rule, got %v", got)
	}
}

func titles(rules []*sigma.Compiled) []string {
	out := make([]string, 0, len(rules))
	for _, c := range rules {
		out = append(out, c.Rule.Title)
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Every rule of this repository has to end up somewhere the records it is
// written for will reach it. This is the test that would have caught the index
// being inert: it counts how many of the rules the index can actually narrow.
func TestMostRulesOfThisRepositoryAreIndexed(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	res, err := sigma.LoadDir(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Skip("no rules")
	}

	indexed := 0
	for _, c := range res.Rules {
		if len(requiredEventIDs(c)) > 0 {
			indexed++
		}
	}
	t.Logf("%d of %d rules are filed under an event identifier", indexed, len(res.Rules))
	// The rules that cannot be indexed are the ones whose identifier sits
	// behind an or, which is a handful. If this drops to a third, the
	// derivation broke again.
	if indexed*2 < len(res.Rules) {
		t.Errorf("only %d of %d rules are indexed; the derivation is probably inert again",
			indexed, len(res.Rules))
	}
}

func repoRootForTest() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// A rule states what evidence it was written for in its logsource, and most of
// the public corpus states it nowhere else. Letting a Zeek rule see a Windows
// record is not a near miss; it is a false positive carrying a rule's name.
func TestARuleOnlySeesTheEvidenceItWasWrittenFor(t *testing.T) {
	zeekRule := compile(t, `
title: Suspicious DNS
logsource:
    product: zeek
    service: dns
detection:
    selection:
        query|contains: '.'
    condition: selection
level: medium
`)
	windowsRule := compile(t, `
title: Any Windows event
logsource:
    product: windows
detection:
    selection:
        query|contains: '.'
    condition: selection
level: medium
`)
	anywhere := compile(t, `
title: States nothing
detection:
    selection:
        query|contains: '.'
    condition: selection
level: low
`)

	idx := newRuleIndex([]*sigma.Compiled{zeekRule, windowsRule, anywhere})

	dns := &event.Event{
		Origin: event.Origin{Product: "zeek", Service: "dns"},
		Raw:    event.Fields{"query": "evil.example.com"},
	}
	got := titles(idx.forEvent(dns))
	if has(got, "Any Windows event") {
		t.Errorf("a Windows rule was offered a Zeek record: %v", got)
	}
	if !has(got, "Suspicious DNS") || !has(got, "States nothing") {
		t.Errorf("the rules that do apply were not offered: %v", got)
	}

	// The same field on Windows evidence: the Zeek rule must not see it.
	win := &event.Event{
		Origin: event.Origin{Product: "windows", Service: "security"},
		Raw:    event.Fields{"query": "evil.example.com"},
	}
	got = titles(idx.forEvent(win))
	if has(got, "Suspicious DNS") {
		t.Errorf("a Zeek rule was offered a Windows record: %v", got)
	}

	// A rule naming only the product still applies to every service of it.
	if !has(got, "Any Windows event") {
		t.Errorf("a rule naming only the product did not apply: %v", got)
	}
}

// The rules of this repository identify their evidence inside the detection,
// so none of them may be filtered out by a logsource they do not rely on.
func TestTheRulesOfThisRepositoryStillSeeTheirEvidence(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	res, err := sigma.LoadDir(filepath.Join(root, "rules", "windows"))
	if err != nil {
		t.Fatal(err)
	}
	idx := newRuleIndex(res.Rules)

	// A Sysmon record as the reader labels one.
	e := &event.Event{
		Origin: event.Origin{Product: "windows", Service: "sysmon"},
		Raw:    event.Fields{"EventID": "1", "Channel": "Microsoft-Windows-Sysmon/Operational"},
	}
	if len(idx.forEvent(e)) == 0 {
		t.Error("no rule was offered a Sysmon process creation")
	}
}

// labelled builds a record the way a reader labels one, which is the only shape
// the logsource filter ever sees.
func labelled(producer, service string, id int, fields map[string]string) *event.Event {
	if fields == nil {
		fields = map[string]string{}
	}
	flat := winevent.Flat{Producer: producer, EventID: id, Fields: fields}
	raw := event.Fields{"EventID": strconv.Itoa(id)}
	for k, v := range fields {
		raw[k] = v
	}
	return &event.Event{
		Origin: event.Origin{
			Product:    "windows",
			Service:    service,
			Categories: winevent.Categories(flat),
		},
		Raw: raw,
	}
}

// readerRecords is one record of every shape the readers actually produce, as
// they actually label it. Not a sample: the point is that a rule written for
// any of them reaches it.
func readerRecords() []*event.Event {
	var out []*event.Event
	for id := 1; id <= 29; id++ {
		out = append(out, labelled("Microsoft-Windows-Sysmon", "sysmon", id, nil))
	}
	for _, t := range []string{"CreateKey", "DeleteKey"} {
		out = append(out, labelled("Microsoft-Windows-Sysmon", "sysmon", 12, map[string]string{"EventType": t}))
	}
	for _, id := range []int{4624, 4625, 4662, 4672, 4688, 4698, 4720, 4732, 4768, 1102} {
		out = append(out, labelled("Microsoft-Windows-Security-Auditing", "security", id, nil))
	}
	for _, id := range []int{4103, 4104} {
		out = append(out, labelled("Microsoft-Windows-PowerShell", "powershell", id, nil))
	}
	out = append(out,
		labelled("Microsoft-Windows-Eventlog", "system", 104, nil),
		labelled("Service Control Manager", "system", 7036, nil),
		&event.Event{Origin: event.Origin{Product: "linux", Service: "auditd", Categories: []string{"process_creation"}}, Raw: event.Fields{}},
		&event.Event{Origin: event.Origin{Product: "linux", Service: "auditd"}, Raw: event.Fields{}},
		&event.Event{Origin: event.Origin{Product: "zeek", Service: "dns"}, Raw: event.Fields{}},
		&event.Event{Origin: event.Origin{Product: "zeek", Service: "conn"}, Raw: event.Fields{}},
		&event.Event{Origin: event.Origin{Product: "zeek", Service: "http"}, Raw: event.Fields{}},
		// files.log: what rules/network/zeek_files_pe_over_cleartext_http.yml is written against.
		&event.Event{Origin: event.Origin{Product: "zeek", Service: "files"}, Raw: event.Fields{}},
	)
	return out
}

// Every rule in this repository has to be able to receive at least one record
// the readers produce. Not "match it" — receive it, which is the step before
// matching and the one that has no symptom.
//
// This is the test that was missing. The logsource filter went in and nothing
// filled Origin.Categories, so the eight rules of this repository that declare
// a category were filtered out of every record in every run: they loaded, they
// counted as loaded, they appeared under "loaded but silent", and the output was
// a smaller number of findings with nothing to say why. The test above did not
// catch it because it only asks whether *some* rule reaches a Sysmon 1, and the
// one rule without a category always did.
func TestEveryRuleOfThisRepositoryCanReceiveARecord(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	res, err := sigma.LoadDir(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Fatal("no rules")
	}

	records := readerRecords()
	for _, c := range res.Rules {
		reachable := false
		for _, e := range records {
			if applies(c, e) {
				reachable = true
				break
			}
		}
		if !reachable {
			ls := c.Rule.Logsource
			t.Errorf("%q can never be offered a record: its logsource asks for "+
				"product %q, service %q, category %q, and no reader labels anything that way",
				c.Rule.Title, ls.Product, ls.Service, ls.Category)
		}
	}
}

// And the same question over the public corpus, where the answer is a number
// rather than a pass.
//
// Most of what cannot be reached cannot be reached for good reasons: a rule for
// macOS, for Azure sign-in logs or for a proxy has no reader here and should
// not have one invented. So this does not demand zero. It demands that the
// figure not grow: it was 677 of 3,162 when the category table was written, and
// an increase means a category stopped being derived and a set of rules went
// quiet without saying so.
func TestTheReachableShareOfThePublicCorpusDoesNotShrink(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	dir := filepath.Join(root, "tools", "sigmahq", "rules")
	if _, err := os.Stat(dir); err != nil {
		skipOrFailHere(t, "the public corpus is not on this machine (see tests/README.md)")
		return
	}
	res, err := sigma.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	records := readerRecords()
	var unreachable []string
	for _, c := range res.Rules {
		reachable := false
		for _, e := range records {
			if applies(c, e) {
				reachable = true
				break
			}
		}
		if !reachable {
			unreachable = append(unreachable, c.Rule.Title)
		}
	}

	t.Logf("%d of %d rules cannot be offered any record these readers produce",
		len(unreachable), len(res.Rules))
	// The figure when this was measured, on 3,162 rules. A corpus that has
	// grown will have more of both, so the share is what is compared.
	const measuredUnreachable, measuredTotal = 677, 3162
	allowed := len(res.Rules) * measuredUnreachable / measuredTotal
	if len(unreachable) > allowed+len(res.Rules)/100 {
		t.Errorf("%d of %d rules are unreachable; at the share measured when the category "+
			"table was written it would be about %d, so something stopped being derived",
			len(unreachable), len(res.Rules), allowed)
	}
}

// skipOrFailHere turns a missing corpus into a failure when the environment
// says the corpus must be there, which is what CI says.
func skipOrFailHere(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("RASTRO_REQUIRE_TOOLS") == "1" {
		t.Fatal(why)
	}
	t.Skip(why)
}
