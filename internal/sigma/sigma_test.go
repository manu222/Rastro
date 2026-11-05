package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// load compiles a rule written inline. The rules of this repository are loaded
// from disk further down; these are for the cases a real rule would not show.
func load(t *testing.T, body string) *Compiled {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("rule did not load: %v", err)
	}
	return c
}

func refuse(t *testing.T, body string) *Unsupported {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("the rule loaded and it should have been refused")
	}
	u, ok := err.(*Unsupported)
	if !ok {
		t.Fatalf("refused with the wrong kind of error: %T %v", err, err)
	}
	return u
}

// Every rule in this repository has to load. If one stops loading, the rule
// changed or the loader broke, and either way the detection it describes is not
// running.
func TestEveryRuleOfThisRepositoryLoads(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	res, err := LoadDir(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range res.Refused {
		t.Errorf("refused: %v", u)
	}
	if len(res.Rules) == 0 {
		t.Fatal("no rules loaded at all")
	}
	t.Logf("%d rules loaded", len(res.Rules))

	// Each one has to have a title and a condition that resolves, because both
	// go in the report beside the finding.
	for _, c := range res.Rules {
		if c.Rule.Title == "" {
			t.Errorf("%s: no title", c.Rule.Path)
		}
		if c.Condition == nil {
			t.Errorf("%s: no condition", c.Rule.Title)
		}
	}
}

// The mistake this whole package exists to catch: a condition that names a
// selection which is not there. pySigma will not always complain, Hayabusa
// loads the rule, and the rule then filters nothing or matches nothing for the
// rest of its life.
func TestATypoInTheConditionRefusesTheRule(t *testing.T) {
	u := refuse(t, `
title: A rule with a typo
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    filter_main_system:
        Image|endswith: '\svchost.exe'
    condition: selection and not filter_main_sytsem
level: high
`)
	if u.Feature != FeatureCondition {
		t.Errorf("refused for the wrong reason: %+v", u)
	}
	if !strings.Contains(u.Reason, "filter_main_sytsem") {
		t.Errorf("the refusal does not name the typo: %s", u.Reason)
	}
}

// The quieter version of the same mistake: a quantifier whose pattern matches
// none of the rule's selections. "1 of nothing" is false and "all of nothing"
// is true, so a misspelled prefix silently turns a filter on or off.
func TestAQuantifierThatMatchesNothingRefusesTheRule(t *testing.T) {
	u := refuse(t, `
title: A rule with an empty group
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    filter_main_known:
        Image|endswith: '\svchost.exe'
    condition: selection and not 1 of filter_mian_*
level: high
`)
	if u.Feature != FeatureCondition {
		t.Errorf("refused for the wrong reason: %+v", u)
	}
}

// A regular expression RE2 cannot compile has to refuse the rule at load time.
// Sigma assumes PCRE and Go does not have it, and the difference must not be
// discovered on an unlucky event in the middle of a case.
func TestARegularExpressionGoCannotCompileRefusesTheRule(t *testing.T) {
	u := refuse(t, `
title: A rule with a lookahead
logsource:
    product: windows
detection:
    selection:
        CommandLine|re: '(?=.*foo)(?=.*bar)'
    condition: selection
level: high
`)
	if u.Feature != FeatureRegexp {
		t.Errorf("refused for the wrong reason: %+v", u)
	}
}

func TestAggregationAndCorrelationAreRefusedByName(t *testing.T) {
	agg := refuse(t, `
title: A rule that counts
logsource:
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection | count() by TargetUserName > 10
level: high
`)
	if agg.Feature != FeatureAggregation {
		t.Errorf("aggregation: %+v", agg)
	}

	corr := refuse(t, `
title: A correlation
correlation:
    type: event_count
    rules:
        - some_rule
    timespan: 5m
    condition:
        gte: 10
`)
	if corr.Feature != FeatureCorrelation {
		t.Errorf("correlation: %+v", corr)
	}
}

// A placeholder is something only the deployment knows. The engine supports the
// modifier; a rule using it is refused only while nobody has said what the
// placeholder means, and the refusal says which one is missing.
func TestPlaceholdersRefuseUntilConfigured(t *testing.T) {
	body := `
title: Logon from an unexpected workstation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    filter_expected:
        WorkstationName|expand: '%Workstations%'
    condition: selection and not filter_expected
level: medium
`
	u := refuse(t, body)
	if u.Feature != FeaturePlaceholder {
		t.Errorf("refused for the wrong reason: %+v", u)
	}
	if !strings.Contains(u.Reason, "%Workstations%") {
		t.Errorf("the refusal does not name the placeholder: %s", u.Reason)
	}

	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFileWith(path, Options{Placeholders: map[string][]string{
		"Workstations": {"PC01", "PC02"},
	}})
	if err != nil {
		t.Fatalf("the rule did not load with the placeholder filled in: %v", err)
	}
	// Both values have to be there: a placeholder with two fills is two
	// alternatives, not the first one.
	test := c.Selections["filter_expected"][0][0]
	if len(test.Values) != 1 {
		t.Fatalf("expected one matcher holding the alternatives: %+v", test)
	}
	if !test.Values[0].Match("PC02") {
		t.Errorf("the second value of the placeholder was dropped: %s", test.Values[0])
	}
}

func TestModifiersMatchWhatTheySay(t *testing.T) {
	cases := []struct {
		name    string
		mods    []string
		value   string
		match   []string
		nomatch []string
	}{
		{
			name:    "exact is case insensitive",
			value:   "powershell.exe",
			match:   []string{"powershell.exe", "POWERSHELL.EXE", "PowerShell.exe"},
			nomatch: []string{"powershell.exe.bak", "notpowershell.exe"},
		},
		{
			name:    "endswith",
			mods:    []string{"endswith"},
			value:   `\rundll32.exe`,
			match:   []string{`C:\Windows\System32\rundll32.exe`, `c:\windows\system32\RUNDLL32.EXE`},
			nomatch: []string{`C:\Windows\System32\rundll32.exe.txt`, "rundll32.exe"},
		},
		{
			name:    "startswith",
			mods:    []string{"startswith"},
			value:   `C:\Users\Public`,
			match:   []string{`C:\Users\Public\a.exe`},
			nomatch: []string{`D:\Users\Public\a.exe`},
		},
		{
			name:    "contains",
			mods:    []string{"contains"},
			value:   "MiniDump",
			match:   []string{"rundll32 comsvcs.dll, MiniDump 123 c:\\x.dmp full", "minidump"},
			nomatch: []string{"mini dump"},
		},
		{
			name:    "a wildcard inside a value",
			value:   `C:\Users\Public\a*.exe`,
			match:   []string{`C:\Users\Public\a.exe`, `C:\Users\Public\abc123.exe`},
			nomatch: []string{`C:\Users\Public\b.exe`, `C:\Users\Public\a.dll`},
		},
		{
			name:    "a leading wildcard",
			value:   `*\rundll32.exe`,
			match:   []string{`C:\Windows\System32\rundll32.exe`, `\\server\share\rundll32.exe`},
			nomatch: []string{"rundll32.exe"},
		},
		{
			// Verified against pySigma, because guessing it would have been
			// indefensible: SigmaString turns this value into the literal text
			// C:\Users*\AppData\Local\Temp*.exe. A backslash in front of an
			// asterisk escapes the asterisk and disappears, so a rule written
			// this way does not match any path - it matches a path with a
			// literal asterisk in it. Rule authors avoid the form, and an
			// engine that treated it as a wildcard would fire where every
			// other Sigma backend stays quiet.
			name:    "a backslash before an asterisk escapes it",
			value:   `C:\Users\*\AppData\Local\Temp\*.exe`,
			match:   []string{`C:\Users*\AppData\Local\Temp*.exe`},
			nomatch: []string{`C:\Users\manu\AppData\Local\Temp\a.exe`},
		},
		{
			name:    "a single character wildcard",
			value:   "cmd?.exe",
			match:   []string{"cmd1.exe", "cmdX.exe"},
			nomatch: []string{"cmd.exe", "cmd12.exe"},
		},
		{
			name:  "windash accepts the dashes Windows accepts",
			mods:  []string{"contains", "windash"},
			value: "-enc",
			match: []string{
				"powershell -enc JABd", "powershell /enc JABd",
				"powershell –enc JABd", "powershell —enc JABd",
			},
			nomatch: []string{"powershell encode"},
		},
		{
			name:    "cidr",
			mods:    []string{"cidr"},
			value:   "172.16.66.0/24",
			match:   []string{"172.16.66.1", "172.16.66.254"},
			nomatch: []string{"172.16.67.1", "-", "", "not an address"},
		},
		{
			name:    "a regular expression",
			mods:    []string{"re"},
			value:   `^[A-Z]:\\Users\\[^\\]+\\Downloads\\`,
			match:   []string{`C:\Users\manu\Downloads\a.exe`},
			nomatch: []string{`C:\Users\manu\Desktop\a.exe`, `c:\users\manu\downloads\a.exe`},
		},
		{
			name:    "a case insensitive regular expression",
			mods:    []string{"re", "i"},
			value:   `^[a-z]:\\users\\`,
			match:   []string{`C:\Users\manu\a.exe`},
			nomatch: []string{`\\server\users\manu`},
		},
		{
			name:  "base64offset finds a string at any alignment",
			mods:  []string{"base64offset", "contains"},
			value: "Invoke-Mimikatz",
			// The three expansions of the reference implementation, each
			// embedded the way it would appear inside a longer command.
			match: []string{
				"powershell -enc SW52b2tlLU1pbWlrYXR6AAAA",
				"powershell -enc AAludm9rZS1NaW1pa2F0eAAA",
				"powershell -enc AAAJbnZva2UtTWltaWthdHAA",
			},
			nomatch: []string{"powershell -enc AAAAAAAA"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := compileValue(c.value, c.mods, Options{})
			if err != nil {
				t.Fatalf("did not compile: %v", err)
			}
			for _, v := range c.match {
				if !m.Match(v) {
					t.Errorf("%s should match %q", m, v)
				}
			}
			for _, v := range c.nomatch {
				if m.Match(v) {
					t.Errorf("%s should not match %q", m, v)
				}
			}
		})
	}
}

// The published expansion of Invoke-Mimikatz, kept because the arithmetic was
// wrong the first time and the error was invisible: a tail one character short
// matches more rather than less.
func TestBase64OffsetMatchesTheReferenceExpansion(t *testing.T) {
	want := []string{"SW52b2tlLU1pbWlrYXR6", "ludm9rZS1NaW1pa2F0e", "JbnZva2UtTWltaWthdH"}
	got := expandBase64Offsets([]string{"Invoke-Mimikatz"})
	if len(got) != len(want) {
		t.Fatalf("want %d expansions, got %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expansion %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

// A backslash in a Sigma value is a backslash, because rules are full of
// Windows paths. Getting this wrong would turn every path into a pattern.
func TestBackslashesAreLiteralAndWildcardsCanBeEscaped(t *testing.T) {
	m, err := compileValue(`C:\Windows\System32\cmd.exe`, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, isLiteral := m.(literal); !isLiteral {
		t.Errorf("a plain Windows path compiled to %T instead of a literal comparison", m)
	}
	if !m.Match(`c:\windows\system32\cmd.exe`) {
		t.Error("a path did not match itself")
	}

	esc, err := compileValue(`report\*.txt`, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !esc.Match("report*.txt") {
		t.Error("an escaped asterisk should match a literal asterisk")
	}
}

// null is a question about the record, not about a value, and it works only
// because the flattener never writes a field the provider left out.
func TestNullAsksWhetherTheFieldIsThere(t *testing.T) {
	c := load(t, `
title: A rule about an absent field
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        ParentImage: null
    condition: selection
level: low
`)
	var found bool
	for _, test := range c.Selections["selection"][0] {
		if test.Field == "ParentImage" {
			found = true
			if !test.Null {
				t.Errorf("ParentImage: null did not compile to a question about absence: %+v", test)
			}
		}
	}
	if !found {
		t.Error("the field was dropped entirely")
	}
}

func TestFieldrefNamesAnotherField(t *testing.T) {
	c := load(t, `
title: A rule comparing two fields
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        Image|fieldref: ParentImage
    condition: selection
level: low
`)
	for _, test := range c.Selections["selection"][0] {
		if test.Field == "Image" {
			if test.Ref != "ParentImage" {
				t.Errorf("fieldref did not record the other field: %+v", test)
			}
			return
		}
	}
	t.Error("the fieldref test was dropped")
}

// A keyword searches every field, and that definition is written down rather
// than left to be inferred from behaviour.
func TestKeywordsSearchEveryField(t *testing.T) {
	c := load(t, `
title: A rule with keywords
logsource:
    product: linux
detection:
    keywords:
        - 'command not allowed'
        - 'authentication failure'
    condition: keywords
level: low
`)
	sel := c.Selections["keywords"]
	if len(sel) != 2 {
		t.Fatalf("two keywords should be two alternatives: %+v", sel)
	}
	test := sel[0][0]
	if test.Field != "" {
		t.Errorf("a keyword should not be bound to a field: %q", test.Field)
	}
	// Plain keywords are substring tests, which is what a rule written against
	// a message means by one.
	if !test.Values[0].Match("sudo: user NOT in sudoers; command not allowed here") {
		t.Errorf("a keyword did not match a message containing it: %s", test.Values[0])
	}
}

// A list of maps under one selection means "any of these shapes", and a map
// means "all of these fields". Getting the two the wrong way round would turn
// every multi-shape rule into one that almost never fires.
func TestListOfMapsIsOrAndAMapIsAnd(t *testing.T) {
	c := load(t, `
title: Shapes
logsource:
    product: windows
detection:
    selection:
        - Image|endswith: '\a.exe'
          CommandLine|contains: 'x'
        - Image|endswith: '\b.exe'
    condition: selection
level: low
`)
	sel := c.Selections["selection"]
	if len(sel) != 2 {
		t.Fatalf("want two alternative shapes, got %d", len(sel))
	}
	if len(sel[0]) != 2 {
		t.Errorf("the first shape should test two fields: %+v", sel[0])
	}
	if len(sel[1]) != 1 {
		t.Errorf("the second shape should test one field: %+v", sel[1])
	}
}

// "all" turns a list of values for one field from alternatives into
// requirements. It is the difference between a command line that mentions
// comsvcs.dll and one that mentions comsvcs.dll AND MiniDump.
func TestAllTurnsAlternativesIntoRequirements(t *testing.T) {
	c := load(t, `
title: All of them
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
level: high
`)
	test := c.Selections["selection"][0][0]
	if !test.All {
		t.Error("the all modifier was lost")
	}
	if len(test.Values) != 2 {
		t.Errorf("want two required values, got %d", len(test.Values))
	}
}

func TestConditionGrammar(t *testing.T) {
	known := map[string]bool{"a": true, "b": true, "c": true, "filter_one": true, "filter_two": true}
	cases := []string{
		"a",
		"a and b",
		"a or b",
		"a and not b",
		"not a",
		"a and (b or c)",
		"(a or b) and not c",
		"1 of filter_*",
		"all of filter_*",
		"a and not 1 of filter_*",
		"all of them",
		"any of filter_*",
	}
	for _, text := range cases {
		if _, err := parseCondition(text, known); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}

	bad := []string{
		"",
		"a and",
		"and a",
		"a and (b",
		"a and b)",
		"d",
		"1 of nothing_*",
		"1 a",
	}
	for _, text := range bad {
		if _, err := parseCondition(text, known); err == nil {
			t.Errorf("%q should not have parsed", text)
		}
	}
}

// A condition written as a YAML block scalar arrives with newlines in it, and
// a rule that fails to load over whitespace is a rule that silently stops
// running.
func TestAMultiLineConditionIsRead(t *testing.T) {
	c := load(t, `
title: A long condition
logsource:
    product: windows
detection:
    selection_a:
        EventID: 1
    selection_b:
        Image|endswith: '\cmd.exe'
    condition: >
        selection_a and
        selection_b
level: low
`)
	if c.Condition.String() != "(selection_a and selection_b)" {
		t.Errorf("condition: %s", c.Condition)
	}
}

// A list of conditions means the rule fires on any of them.
func TestAListOfConditionsIsAnOr(t *testing.T) {
	c := load(t, `
title: Two conditions
logsource:
    product: windows
detection:
    a:
        EventID: 1
    b:
        EventID: 2
    condition:
        - a
        - b
level: low
`)
	if c.Condition.String() != "(a or b)" {
		t.Errorf("condition: %s", c.Condition)
	}
}

// Refusals are counted by cause so that what to implement next is a number
// rather than an opinion.
func TestRefusalsAreCountedByCause(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.yml", "title: Fine\ndetection:\n    selection:\n        EventID: 1\n    condition: selection\n")
	write("agg.yml", "title: Counts\ndetection:\n    selection:\n        EventID: 1\n    condition: selection | count() by Image > 5\n")
	write("typo.yml", "title: Typo\ndetection:\n    selection:\n        EventID: 1\n    condition: selection and nope\n")

	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 {
		t.Errorf("want one rule loaded, got %d", len(res.Rules))
	}
	counts := res.ByFeature()
	if counts[FeatureAggregation] != 1 || counts[FeatureCondition] != 1 {
		t.Errorf("refusals counted wrong: %v", counts)
	}
}
