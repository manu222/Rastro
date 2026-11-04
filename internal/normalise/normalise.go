// Package normalise renders the values a parser hands back as the text the
// provider originally wrote.
//
// It exists because of a measured problem. Sysmon writes an access mask as the
// text "0x1010"; one version of the Go EVTX parser returns that same field as
// the number 4112, and a rule matching "0x1010" then finds nothing and says so
// by staying quiet. The field did not change. The parser did.
//
// So this is not a canonical form of our own invention. Imposing one would
// break rules rather than fix them: a process identifier is decimal in Sysmon
// and hexadecimal in the Security channel, both correct, both written that way
// by the provider, and both relied upon by rules somebody else wrote. What this
// package does is narrower and safer — it undoes the parser's reshaping and
// puts the provider's own text back.
//
// Knowledge of what each provider writes is data, not code: one table per
// provider, which is the same thing the provider's own manifest declares
// (win:HexInt32 against win:UInt32 and so on). The tables here were seeded from
// the pinned corpus and should be replaced by the manifests when a machine with
// the providers installed is available; what the corpus never showed, the
// corpus cannot confirm.
//
// What it cannot do is invent knowledge. A field nobody declared is passed
// through untouched, and that is a real way to miss a detection. The answer is
// not to guess but to notice: every undeclared field that arrives in a shape
// other than text is recorded, so that the gap shows up as a failing audit in
// CI and as a warning in the report for the case at hand, instead of as silence.
package normalise

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
)

// Form is the shape in which a provider writes a field's value as text.
type Form uint8

const (
	// FormUnset means no table declares this field.
	FormUnset Form = iota
	// FormText is free text: whatever the provider wrote is the value.
	FormText
	// FormDecimal is an integer written in base ten.
	FormDecimal
	// FormHex is an integer written with a 0x prefix, lower case.
	FormHex
	// FormBool is written as true or false, lower case.
	FormBool
	// FormMessageRef is a reference into the provider's message table, written
	// as %%1833. It is never converted: the number is an index, and rendering
	// it as an integer would turn a label into arithmetic.
	FormMessageRef
	// FormStructured is a nested value. It is kept as compact JSON so that the
	// report can still show it, and rules can still match text inside it.
	FormStructured
)

func (f Form) String() string {
	switch f {
	case FormText:
		return "text"
	case FormDecimal:
		return "decimal"
	case FormHex:
		return "hex"
	case FormBool:
		return "bool"
	case FormMessageRef:
		return "message_ref"
	case FormStructured:
		return "structured"
	default:
		return "undeclared"
	}
}

// Table says how one provider writes its fields.
type Table struct {
	Producer string
	Fields   map[string]Form
}

// Result is one rendered value.
type Result struct {
	Text string
	// Declared reports whether a table covered this field.
	Declared bool
	// Restored reports that the parser had changed the shape and the provider's
	// own text was put back. Useful for telling a quiet pipeline from one that
	// is doing work.
	Restored bool
}

// Gap is a field that arrived in a shape nobody declared, or in a shape that
// contradicts its declaration.
type Gap struct {
	Producer string
	Field    string
	// Shape is the Go type the parser produced: int64, bool, float64.
	Shape string
	// Declared is the form the table claimed, if any. An undeclared field has
	// FormUnset here; a contradiction has something else.
	Declared Form
	// Sample is one value, so that whoever reads the warning can see what the
	// pipeline was dealing with.
	Sample string
	Count  int
}

// Normaliser renders values and keeps a record of what it did not understand.
//
// Rendering takes no locks: it is called for every field of every event, and a
// large case is a million events. Only the recording of a gap locks, and a gap
// is by definition rare — once a field has been seen, later sightings only
// increment a counter.
type Normaliser struct {
	tables map[string]*Table

	mu   sync.Mutex
	gaps map[string]*Gap
}

// New builds a normaliser from a set of provider tables.
func New(tables ...*Table) *Normaliser {
	n := &Normaliser{
		tables: make(map[string]*Table, len(tables)),
		gaps:   map[string]*Gap{},
	}
	for _, t := range tables {
		n.tables[t.Producer] = t
	}
	return n
}

// Render turns one raw value into the text the provider wrote.
//
// An error means the value could not be rendered without losing information,
// which is treated as worth stopping for rather than papering over: a number
// that does not survive the trip is a wrong number in a report.
func (n *Normaliser) Render(producer, field string, v any) (Result, error) {
	form := FormUnset
	if t, ok := n.tables[producer]; ok {
		form = t.Fields[field]
	}

	// A string is the provider's own text. Nothing to restore, whatever the
	// table says, so this is both the fast path and the safe one.
	if s, ok := v.(string); ok {
		return Result{Text: s, Declared: form != FormUnset}, nil
	}
	if v == nil {
		return Result{Text: "", Declared: form != FormUnset}, nil
	}

	switch val := v.(type) {
	case bool:
		if form == FormUnset {
			n.note(producer, field, "bool", form, strconv.FormatBool(val))
		}
		return Result{Text: strconv.FormatBool(val), Declared: form != FormUnset, Restored: true}, nil

	case map[string]any, []any:
		raw, err := json.Marshal(val)
		if err != nil {
			return Result{}, fmt.Errorf("%s.%s: cannot render nested value: %w", producer, field, err)
		}
		if form == FormUnset {
			n.note(producer, field, "structured", form, truncate(string(raw)))
		}
		return Result{Text: string(raw), Declared: form != FormUnset, Restored: true}, nil
	}

	u, signed, err := asInteger(v)
	if err != nil {
		return Result{}, fmt.Errorf("%s.%s: %w", producer, field, err)
	}

	var text string
	switch form {
	case FormHex:
		text = "0x" + strconv.FormatUint(u, 16)
	case FormMessageRef:
		// The parser gave a number for something the provider writes as a
		// label. Rendering it either way would be a guess, so it goes out as
		// plain digits and the contradiction is recorded.
		text = formatInteger(u, signed)
		n.note(producer, field, "integer", form, text)
	default:
		text = formatInteger(u, signed)
		if form == FormUnset {
			n.note(producer, field, "integer", form, text)
		}
	}
	return Result{Text: text, Declared: form != FormUnset, Restored: true}, nil
}

// asInteger widens whatever numeric type the parser produced, refusing the ones
// that cannot be carried exactly.
//
// The float case is not theoretical. Decoding EVTX through encoding/json turns
// every number into a float64, and this corpus contains the value
// 18446744073709551615 — the largest unsigned 64-bit integer. As a float64 it
// becomes 18446744073709551616, so a pipeline that quietly accepts floats
// reports a number that was never in the evidence. Refusing is the only honest
// option; the fix is to decode with json.Number, which this function accepts.
func asInteger(v any) (u uint64, signed bool, err error) {
	switch val := v.(type) {
	case int:
		return toUnsigned(int64(val))
	case int8:
		return toUnsigned(int64(val))
	case int16:
		return toUnsigned(int64(val))
	case int32:
		return toUnsigned(int64(val))
	case int64:
		return toUnsigned(val)
	case uint:
		return uint64(val), false, nil
	case uint8:
		return uint64(val), false, nil
	case uint16:
		return uint64(val), false, nil
	case uint32:
		return uint64(val), false, nil
	case uint64:
		return val, false, nil
	case json.Number:
		if n, e := strconv.ParseUint(val.String(), 10, 64); e == nil {
			return n, false, nil
		}
		if n, e := strconv.ParseInt(val.String(), 10, 64); e == nil {
			return toUnsigned(n)
		}
		return 0, false, fmt.Errorf("value %q is not an integer", val.String())
	case float64:
		if val != math.Trunc(val) {
			return 0, false, fmt.Errorf("value %v is not a whole number", val)
		}
		if math.Abs(val) > 1<<53 {
			return 0, false, fmt.Errorf(
				"value %v arrived as a float and is too large to be exact; decode with json.Number", val)
		}
		return toUnsigned(int64(val))
	}
	return 0, false, fmt.Errorf("value of type %T cannot be rendered", v)
}

func toUnsigned(i int64) (uint64, bool, error) {
	if i < 0 {
		return uint64(i), true, nil
	}
	return uint64(i), false, nil
}

func formatInteger(u uint64, signed bool) string {
	if signed {
		return strconv.FormatInt(int64(u), 10)
	}
	return strconv.FormatUint(u, 10)
}

func (n *Normaliser) note(producer, field, shape string, declared Form, sample string) {
	key := producer + "\x00" + field + "\x00" + shape
	n.mu.Lock()
	defer n.mu.Unlock()
	if g, ok := n.gaps[key]; ok {
		g.Count++
		return
	}
	n.gaps[key] = &Gap{
		Producer: producer, Field: field, Shape: shape,
		Declared: declared, Sample: sample, Count: 1,
	}
}

// Gaps returns what the normaliser did not understand, sorted so that two runs
// over the same evidence produce the same list.
//
// This is the whole point of the package being able to admit ignorance. In CI
// the list has to be empty against the pinned corpus. In a real case it goes in
// the report: three fields nobody declared is not a crash, but it is a reason
// to trust the rules that touch them a little less, and the analyst is the one
// who should decide that.
func (n *Normaliser) Gaps() []Gap {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Gap, 0, len(n.gaps))
	for _, g := range n.gaps {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Producer != out[j].Producer {
			return out[i].Producer < out[j].Producer
		}
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Shape < out[j].Shape
	})
	return out
}

func truncate(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
