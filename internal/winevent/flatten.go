// Package winevent turns a decoded Windows event record into the flat set of
// named values that detection rules are written against.
//
// It is deliberately separate from the code that opens an .evtx file. Parsing
// is mechanical and depends on a third-party library; flattening is where the
// decisions are, and keeping it here means it can be tested against real
// records held as plain JSON, with no parser involved.
//
// What "flat" means is decided by the rules, not by taste. A Sigma rule says
// EventID and Channel and Image, in one namespace, without caring that Windows
// keeps the first two in a System block and the third in an EventData block. So
// both blocks end up in the same map under their own names.
//
// The full paths are not kept. Level three of the report shows the original
// record by re-reading it from the evidence, so carrying a second copy of every
// field, path-addressed, would cost memory on every event to serve something
// that is served better another way.
package winevent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/manu222/rastro/internal/normalise"
)

// Flat is one record, ready for rule matching.
type Flat struct {
	// Producer is the provider that wrote the record, which is also what
	// decides how its fields are rendered.
	Producer string
	// Channel can be empty. Not every provider writes one — in the pinned
	// corpus the RPC trace provider omits it on all of its 29,523 records — and
	// inventing one from the file name would be a guess presented as a fact.
	Channel  string
	Computer string
	EventID  int
	Time     time.Time

	// Fields is what the rules see.
	Fields map[string]string
	// Shadowed holds System values that an EventData field of the same name
	// displaced. Rare — one record in the whole pinned corpus — but it is a
	// value that was in the evidence, and dropping it silently is not an option.
	Shadowed map[string]string
}

// systemAliases are the extra names Sigma rules use for values that Windows
// keeps as XML attributes. The flattener already emits Provider_Name,
// Execution_ProcessID and so on from the structure itself; these are the
// spellings rule authors actually write, added alongside rather than instead.
var systemAliases = map[string]string{
	"Execution_ProcessID":    "ExecutionProcessID",
	"Execution_ThreadID":     "ExecutionThreadID",
	"Security_UserID":        "SecurityUserID",
	"TimeCreated_SystemTime": "SystemTime",
	"Correlation_ActivityID": "ActivityID",
}

// Flatten builds the flat view of one record.
//
// rec is the decoded record, shaped the way Windows writes it:
// {"Event": {"System": {...}, "EventData": {...}}}.
func Flatten(rec map[string]any, n *normalise.Normaliser) (Flat, error) {
	ev, ok := rec["Event"].(map[string]any)
	if !ok {
		return Flat{}, fmt.Errorf("record has no Event element")
	}
	system, _ := ev["System"].(map[string]any)
	if system == nil {
		return Flat{}, fmt.Errorf("record has no System element")
	}

	f := Flat{Fields: make(map[string]string, 32)}
	// Most providers give a name. Some only register a GUID — the RPC trace
	// provider in the pinned corpus is one, and it accounts for 29,523 records.
	// The GUID is then what identifies it, which is honest: it is what the
	// record actually says. No table matches it, so its reshaped fields are
	// reported as gaps, which is the correct answer rather than a convenient one.
	f.Producer = attribute(system, "Provider", "Name")
	if f.Producer == "" {
		f.Producer = attribute(system, "Provider", "Guid")
	}

	// The System block is defined by Windows itself and is the same whichever
	// provider wrote the record, so its values are rendered here rather than
	// through the per-provider tables.
	for name, raw := range system {
		switch v := raw.(type) {
		case nil:
			// Absent is absent. Writing an empty string would make a rule
			// testing for the field match on nothing.
		case map[string]any:
			// Two shapes live here. An element with attributes, such as
			// Provider or Execution, and an element that has both a value and
			// attributes, such as EventID when the provider sets Qualifiers.
			if text, ok := v["#text"]; ok {
				if s, err := scalar(text); err == nil {
					f.Fields[name] = s
				}
			}
			if attrs, ok := v["#attributes"].(map[string]any); ok {
				for an, av := range attrs {
					s, err := scalar(av)
					if err != nil {
						continue
					}
					key := name + "_" + an
					f.Fields[key] = s
					if alias, ok := systemAliases[key]; ok {
						f.Fields[alias] = s
					}
				}
			}
		default:
			s, err := scalar(raw)
			if err != nil {
				return Flat{}, fmt.Errorf("System.%s: %w", name, err)
			}
			f.Fields[name] = s
		}
	}

	// EventData is the provider's own, so it goes through the provider's table.
	switch data := ev["EventData"].(type) {
	case nil:
		// Some records carry no EventData at all. Twenty-six of them in the
		// pinned corpus.
	case map[string]any:
		for name, raw := range data {
			if name == "#attributes" {
				if attrs, ok := raw.(map[string]any); ok {
					for an, av := range attrs {
						if s, err := scalar(av); err == nil {
							f.Fields["EventData_"+an] = s
						}
					}
				}
				continue
			}
			res, err := n.Render(f.Producer, name, raw)
			if err != nil {
				return Flat{}, fmt.Errorf("EventData.%s: %w", name, err)
			}
			if old, clash := f.Fields[name]; clash {
				if f.Shadowed == nil {
					f.Shadowed = map[string]string{}
				}
				f.Shadowed[name] = old
			}
			f.Fields[name] = res.Text
		}
	default:
		// Not a mapping. Keep it whole rather than guess at its structure.
		raw, err := json.Marshal(data)
		if err != nil {
			return Flat{}, fmt.Errorf("EventData: %w", err)
		}
		f.Fields["EventData"] = string(raw)
	}

	f.Channel = f.Fields["Channel"]
	f.Computer = f.Fields["Computer"]
	if id, err := strconv.Atoi(f.Fields["EventID"]); err == nil {
		f.EventID = id
	}
	if ts := f.Fields["SystemTime"]; ts != "" {
		// Windows writes seven fractional digits, which RFC 3339 accommodates.
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return Flat{}, fmt.Errorf("SystemTime %q: %w", ts, err)
		}
		f.Time = t.UTC()
	}
	return f, nil
}

// scalar renders a System value. These are plain types: Windows does not put
// provider-specific encodings in this block, so there is nothing to restore.
func scalar(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case bool:
		return strconv.FormatBool(val), nil
	case json.Number:
		return val.String(), nil
	case int:
		return strconv.Itoa(val), nil
	case int64:
		return strconv.FormatInt(val, 10), nil
	case uint64:
		return strconv.FormatUint(val, 10), nil
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10), nil
		}
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	case nil:
		return "", nil
	}
	return "", fmt.Errorf("unexpected value of type %T", v)
}

func attribute(block map[string]any, element, name string) string {
	e, ok := block[element].(map[string]any)
	if !ok {
		return ""
	}
	attrs, ok := e["#attributes"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := attrs[name].(string)
	return s
}
