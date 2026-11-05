package sigma

import (
	"path/filepath"
	"strings"
	"testing"
)

// The record these tests run against is the Sysmon 10 that rule 1 is written
// for: one process opening lsass with a mask that includes the right to read
// its memory.
func lsassAccess() map[string]string {
	return map[string]string{
		"EventID":           "10",
		"Channel":           "Microsoft-Windows-Sysmon/Operational",
		"Computer":          "IEWIN7",
		"SourceImage":       `C:\Users\Public\voice_mail.msg.exe`,
		"SourceProcessId":   "1532",
		"TargetImage":       `C:\Windows\System32\lsass.exe`,
		"TargetProcessId":   "264",
		"GrantedAccess":     "0x1010",
		"CallTrace":         `C:\Windows\SYSTEM32\ntdll.dll+4595c|UNKNOWN(01B51600)`,
		"Provider_Name":     "Microsoft-Windows-Sysmon",
		"UtcTime":           "2019-04-30 12:43:43.784",
		"Execution_Process": "1964",
	}
}

func TestAnAndConditionNeedsEveryPart(t *testing.T) {
	c := load(t, `
title: Access to lsass
logsource:
    product: windows
    category: process_access
detection:
    process_access:
        EventID: 10
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains: '0x1010'
    condition: process_access and selection
level: high
`)
	if !c.Matches(lsassAccess()) {
		t.Fatal("the rule did not match the record it was written for")
	}

	// Change one thing at a time and the rule has to stop matching.
	for field, value := range map[string]string{
		"EventID":       "1",
		"TargetImage":   `C:\Windows\System32\svchost.exe`,
		"GrantedAccess": "0x1000",
	} {
		rec := lsassAccess()
		rec[field] = value
		if c.Matches(rec) {
			t.Errorf("still matched with %s = %q", field, value)
		}
	}

	// And a record missing the field entirely must not match either, which is
	// a different case from the field holding something else.
	rec := lsassAccess()
	delete(rec, "GrantedAccess")
	if c.Matches(rec) {
		t.Error("matched a record that does not have the field at all")
	}
}

// The filter is the part that goes wrong quietly. A rule whose filter stops
// working does not fail — it drowns the analyst in the noise it was written to
// remove.
func TestAFilterRemovesWhatItNames(t *testing.T) {
	c := load(t, `
title: Access to lsass with a filter
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
    filter_main_antivirus:
        SourceImage|startswith: 'C:\Program Files\Windows Defender\'
    filter_main_wmi:
        SourceImage|endswith: '\wmiprvse.exe'
    condition: selection and not 1 of filter_main_*
level: high
`)
	if !c.Matches(lsassAccess()) {
		t.Fatal("the rule did not match")
	}

	for _, image := range []string{
		`C:\Program Files\Windows Defender\MsMpEng.exe`,
		`C:\Windows\System32\wbem\wmiprvse.exe`,
	} {
		rec := lsassAccess()
		rec["SourceImage"] = image
		if c.Matches(rec) {
			t.Errorf("the filter did not remove %s", image)
		}
	}
}

func TestAllOfRequiresEverySelection(t *testing.T) {
	c := load(t, `
title: All of them
logsource:
    product: windows
detection:
    selection_id:
        EventID: 10
    selection_target:
        TargetImage|endswith: '\lsass.exe'
    condition: all of selection_*
level: high
`)
	if !c.Matches(lsassAccess()) {
		t.Fatal("all of: did not match when both selections do")
	}
	rec := lsassAccess()
	rec["EventID"] = "11"
	if c.Matches(rec) {
		t.Error("all of: matched with one selection failing")
	}
}

// "all" on a value list is the difference between a command line that mentions
// comsvcs.dll and one that mentions comsvcs.dll AND MiniDump. Rule 11 of this
// repository depends on it.
func TestAllOnAValueListRequiresEveryValue(t *testing.T) {
	c := load(t, `
title: Process dump through comsvcs
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
level: high
`)
	if !c.Matches(map[string]string{
		"CommandLine": `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\x.dmp full`,
	}) {
		t.Error("did not match a command line with both")
	}
	if c.Matches(map[string]string{"CommandLine": `rundll32.exe comsvcs.dll, Something 1 2 3`}) {
		t.Error("matched a command line with only one of the two")
	}
}

// Absence is a question about the record, and it is answerable only because the
// flattener never writes a field the provider left out.
func TestNullMatchesOnlyWhenTheFieldIsMissing(t *testing.T) {
	c := load(t, `
title: A process with no parent recorded
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        ParentImage: null
    condition: selection
level: low
`)
	if !c.Matches(map[string]string{"EventID": "1"}) {
		t.Error("did not match a record without the field")
	}
	if c.Matches(map[string]string{"EventID": "1", "ParentImage": `C:\Windows\explorer.exe`}) {
		t.Error("matched a record that has the field")
	}
	// An empty value is not an absent field. The provider wrote something, and
	// what it wrote was nothing — which is a fact about the record, not a gap
	// in it.
	if c.Matches(map[string]string{"EventID": "1", "ParentImage": ""}) {
		t.Error("an empty value was treated as an absent field")
	}
}

func TestFieldrefComparesTwoFieldsOfTheSameRecord(t *testing.T) {
	c := load(t, `
title: A process whose image is its own parent
logsource:
    product: windows
detection:
    selection:
        Image|fieldref: ParentImage
    condition: selection
level: low
`)
	if !c.Matches(map[string]string{
		"Image":       `C:\Windows\System32\cmd.exe`,
		"ParentImage": `c:\windows\system32\CMD.EXE`,
	}) {
		t.Error("two spellings of the same path should compare equal")
	}
	if c.Matches(map[string]string{
		"Image":       `C:\Windows\System32\cmd.exe`,
		"ParentImage": `C:\Windows\explorer.exe`,
	}) {
		t.Error("two different paths compared equal")
	}
	// Neither field present is not "they are the same".
	if c.Matches(map[string]string{"EventID": "1"}) {
		t.Error("a record with neither field matched a comparison between them")
	}
}

func TestKeywordsAreLookedForInEveryField(t *testing.T) {
	c := load(t, `
title: A keyword rule
logsource:
    product: linux
detection:
    keywords:
        - 'command not allowed'
    condition: keywords
level: low
`)
	if !c.Matches(map[string]string{
		"type": "USER_CMD",
		"msg":  "sudo: user NOT in sudoers ; command not allowed here",
	}) {
		t.Error("the keyword was not found in the field that holds it")
	}
	if c.Matches(map[string]string{"type": "USER_CMD", "msg": "session opened"}) {
		t.Error("matched a record that does not contain the keyword")
	}
}

// A finding has to be able to say why. "Rule fired" is not something an analyst
// can act on.
func TestExplainNamesTheFieldAndThePattern(t *testing.T) {
	c := load(t, `
title: Access to lsass
logsource:
    product: windows
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains: '0x1010'
    filter_main_defender:
        SourceImage|startswith: 'C:\Program Files\Windows Defender\'
    condition: selection and not 1 of filter_main_*
level: high
`)
	rec := lsassAccess()
	if !c.Matches(rec) {
		t.Fatal("the rule did not match")
	}
	hits := c.Explain(rec)
	if len(hits) != 3 {
		t.Fatalf("want three reasons, got %d: %+v", len(hits), hits)
	}

	byField := map[string]Hit{}
	for _, h := range hits {
		byField[h.Field] = h
	}
	if h := byField["TargetImage"]; h.Value != `C:\Windows\System32\lsass.exe` || h.Pattern != `*\lsass.exe` {
		t.Errorf("TargetImage: %+v", h)
	}
	if h := byField["GrantedAccess"]; h.Pattern != "*0x1010*" {
		t.Errorf("GrantedAccess: %+v", h)
	}
	for _, h := range hits {
		if h.Selection != "selection" {
			t.Errorf("a hit came from %q", h.Selection)
		}
		// What a filter looked for is not a reason the rule fired. Listing it
		// would read like evidence when it is the opposite.
		if strings.HasPrefix(h.Selection, "filter") {
			t.Errorf("a filter was reported as a reason: %+v", h)
		}
	}
}

// Only the side of an or that actually matched is a reason.
func TestExplainSkipsTheBranchThatDidNotMatch(t *testing.T) {
	c := load(t, `
title: Either way
logsource:
    product: windows
detection:
    by_image:
        TargetImage|endswith: '\lsass.exe'
    by_pipe:
        PipeName|endswith: '-stdin'
    condition: by_image or by_pipe
level: high
`)
	hits := c.Explain(lsassAccess())
	if len(hits) != 1 || hits[0].Selection != "by_image" {
		t.Errorf("want one reason from by_image, got %+v", hits)
	}
}

// Every rule of this repository has to match at least one shape of record that
// its own test manifest says it should. This is not the equivalence test
// against the reference engine — that comes next and runs over the whole
// corpus — but it does catch a rule that loads, evaluates, and is incapable of
// ever firing.
func TestRulesOfThisRepositoryCanFire(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	res, err := LoadDir(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Skip("no rules")
	}

	for _, c := range res.Rules {
		// A record built out of the rule's own positive selections: every
		// literal and suffix test satisfied, every filter left unsatisfied. If
		// the rule cannot match that, it cannot match anything.
		rec := map[string]string{}
		for name, sel := range c.Selections {
			if strings.HasPrefix(name, "filter") {
				continue
			}
			for _, test := range sel[0] {
				if test.Field == "" || test.Null || test.Ref != "" || len(test.Values) == 0 {
					continue
				}
				// A test with "all" needs every value present at once, which
				// is the whole point of the modifier.
				sample := sampleFor(test.Values[0])
				if test.All {
					var b strings.Builder
					for _, m := range test.Values {
						b.WriteString(sampleFor(m))
						b.WriteString(" ")
					}
					sample = b.String()
				}
				if old, taken := rec[test.Field]; taken {
					// Two selections can test the same field and both have to
					// hold at once, which is how the rundll32 rule pairs a
					// library with an exported function. Joining them works
					// for a substring test and would corrupt anything else, so
					// anything else is left as it was.
					if _, isContains := test.Values[0].(contains); isContains {
						rec[test.Field] = old + " " + sample
					}
					continue
				}
				rec[test.Field] = sample
			}
		}
		if len(rec) == 0 {
			continue
		}
		if !c.Matches(rec) {
			t.Errorf("%s: cannot match a record built from its own selections: %v", c.Rule.Title, rec)
		}
	}
}

// sampleFor invents a value that satisfies a matcher, for the test above only.
// It handles the shapes this repository's rules use and gives up on the rest,
// which is why the test skips a rule it cannot build a record for instead of
// failing it.
func sampleFor(m Matcher) string {
	switch v := m.(type) {
	case literal:
		return v.want
	case cased:
		return v.want
	case contains:
		return "x" + v.want + "x"
	case prefix:
		return v.want + "x"
	case suffix:
		return "x" + v.want
	case anyOf:
		if len(v.of) > 0 {
			return sampleFor(v.of[0])
		}
	case glob:
		return strings.NewReplacer("*", "x", "?", "x").Replace(v.pattern)
	}
	return ""
}
