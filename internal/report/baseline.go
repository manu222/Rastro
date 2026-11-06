package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/sigma"
)

// An incident under investigation is analysed more than once: the evidence
// grows as more machines are collected, and the question each time is what
// changed. A finding is recognised across runs by what it says rather than by
// where it was read, because a record number moves when a channel is exported
// again and a file name changes with the collection.
//
// fingerprint is the rule, the machine, the event's own time and the values
// that made the rule fire. Nothing deduced goes in: an account found through a
// lineage can appear in a later run because a process creation was collected,
// and the finding is still the same finding.
func fingerprint(f Finding) string {
	rule := f.RuleID
	if rule == "" {
		rule = f.Rule
	}
	why := make([]string, 0, len(f.Why))
	for _, w := range f.Why {
		why = append(why, w.Field+"="+w.Value)
	}
	sort.Strings(why)
	h := sha256.Sum256([]byte(strings.Join(append([]string{
		rule, strings.ToLower(f.Host), f.Time.UTC().Format(time.RFC3339Nano),
	}, why...), "\x00")))
	return hex.EncodeToString(h[:8])
}

// assignIDs gives each finding its fingerprint. Two findings that say exactly
// the same thing — a record duplicated by a shipper, say — share it, and the
// second and later get a suffix in report order, so an ID still names one line.
func assignIDs(findings []Finding) {
	seen := map[string]int{}
	for i := range findings {
		id := fingerprint(findings[i])
		seen[id]++
		if n := seen[id]; n > 1 {
			id = fmt.Sprintf("%s-%d", id, n)
		}
		findings[i].ID = id
	}
}

// Comparison is what changed since an earlier report of the same case.
type Comparison struct {
	File      string    `json:"file"`
	Generated time.Time `json:"generated"`
	New       int       `json:"new"`
	Seen      int       `json:"seen_before"`
	Gone      []Gone    `json:"gone"`
}

// Gone is a finding of the earlier report that this one does not have, and
// why that can be. It is not "resolved": a finding disappears when the
// evidence that produced it is not in this run, and nothing here can tell a
// cleaned machine from a collection that left a channel out.
type Gone struct {
	ID     string    `json:"id"`
	Rule   string    `json:"rule"`
	Level  string    `json:"level"`
	Host   string    `json:"host,omitempty"`
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
}

// Compare marks each finding of r as new or seen before against prev, and
// lists what prev had that r does not. loaded is the rule set of this run, so
// that a finding missing because its rule was not loaded says so.
func Compare(r, prev *Report, file string, loaded []*sigma.Compiled) {
	before := map[string]bool{}
	for _, f := range prev.Findings {
		if f.ID == "" {
			// A report written before findings carried an ID.
			f.ID = fingerprint(f)
		}
		before[f.ID] = true
	}
	ruleLoaded := map[string]bool{}
	for _, c := range loaded {
		ruleLoaded[c.Rule.ID] = true
		ruleLoaded[c.Rule.Title] = true
	}

	c := &Comparison{File: file, Generated: prev.Generated, Gone: []Gone{}}
	now := map[string]bool{}
	for i := range r.Findings {
		f := &r.Findings[i]
		now[f.ID] = true
		if before[f.ID] {
			f.Status = "seen before"
			c.Seen++
		} else {
			f.Status = "new"
			c.New++
		}
	}
	for _, f := range prev.Findings {
		id := f.ID
		if id == "" {
			id = fingerprint(f)
		}
		if now[id] {
			continue
		}
		g := Gone{ID: id, Rule: f.Rule, Level: f.Level, Host: f.Host, Time: f.Time}
		if (f.RuleID != "" && ruleLoaded[f.RuleID]) || ruleLoaded[f.Rule] {
			g.Reason = "the rule ran, and the evidence of this run did not produce it"
		} else {
			g.Reason = "the rule is not loaded in this run"
		}
		c.Gone = append(c.Gone, g)
	}
	r.Baseline = c
}
