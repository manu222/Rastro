package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
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

	one := &event.Event{Raw: event.Fields{"EventID": "1", "Image": `C:\Windows\cmd.exe`}}
	got := titles(idx.forEvent(one))
	if !has(got, "Only event 1") || !has(got, "Any event") {
		t.Errorf("a record of event 1 did not meet the rules it should: %v", got)
	}
	if has(got, "Only event 10") {
		t.Errorf("a record of event 1 met a rule that needs event 10: %v", got)
	}

	// A record of an event no rule names still meets the unpinned ones, which
	// is what keeps the index from hiding anything.
	rpc := &event.Event{Raw: event.Fields{"EventID": "0"}}
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
