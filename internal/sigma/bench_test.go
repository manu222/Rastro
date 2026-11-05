package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

// What a rule costs to run decides whether the engine needs an index.
//
// The arithmetic is unforgiving: a case with a million events and the full
// public rule set is a million times four thousand evaluations, so a
// microsecond each is an hour and a nanosecond each is four seconds. Which of
// those this is should be measured before any effort goes into making it
// faster, which is the same reason the event model was measured before it was
// settled.
//
//	go test ./internal/sigma/ -bench . -benchmem

func benchRules(b *testing.B, dir string) []*Compiled {
	b.Helper()
	root, err := repoRoot()
	if err != nil {
		b.Skip("cannot find the repository root")
	}
	res, err := LoadDir(filepath.Join(root, dir))
	if err != nil {
		b.Skip(err.Error())
	}
	if len(res.Rules) == 0 {
		b.Skip("no rules in " + dir)
	}
	return res.Rules
}

// One event against the rules of this repository: what a run over real
// evidence actually costs today.
func BenchmarkThisRepositoryAgainstOneEvent(b *testing.B) {
	rules := benchRules(b, "rules")
	rec := lsassAccess()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range rules {
			r.Matches(rec)
		}
	}
	b.ReportMetric(float64(len(rules)), "rules")
}

// The same event against the whole public corpus, which is the number that
// says whether an index is needed. Skipped unless the corpus is on the
// machine.
func BenchmarkPublicCorpusAgainstOneEvent(b *testing.B) {
	root, err := repoRoot()
	if err != nil {
		b.Skip("cannot find the repository root")
	}
	res, err := LoadDir(filepath.Join(root, "tools", "sigmahq", "rules"))
	if err != nil || len(res.Rules) == 0 {
		b.Skip("the SigmaHQ corpus is not on this machine")
	}
	rec := lsassAccess()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range res.Rules {
			r.Matches(rec)
		}
	}
	b.ReportMetric(float64(len(res.Rules)), "rules")
}

// A single rule, to separate the cost of one evaluation from the cost of
// walking a list of them.
func BenchmarkOneRule(b *testing.B) {
	path := filepath.Join(b.TempDir(), "rule.yml")
	writeBenchRule(b, path)
	c, err := LoadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	rec := lsassAccess()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Matches(rec)
	}
}

// Explaining a match is the second pass, and it only runs on the events that
// matched. This says what that pass costs when it does run.
func BenchmarkExplainAMatch(b *testing.B) {
	path := filepath.Join(b.TempDir(), "rule.yml")
	writeBenchRule(b, path)
	c, err := LoadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	rec := lsassAccess()
	if !c.Matches(rec) {
		b.Fatal("the rule does not match the record this benchmark is built on")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Explain(rec)
	}
}

func writeBenchRule(b *testing.B, path string) {
	b.Helper()
	body := `
title: Access to lsass
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains: '0x1010'
    filter_main_defender:
        SourceImage|startswith: 'C:\Program Files\Windows Defender\'
    filter_main_wmi:
        SourceImage|endswith: '\wmiprvse.exe'
    condition: selection and not 1 of filter_main_*
level: high
`
	if err := writeFile(path, body); err != nil {
		b.Fatal(err)
	}
}

// writeFile is here rather than inline so that the benchmark bodies read as
// benchmarks.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
