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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
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
	// TimeSource names the field Time was read from: UtcTime when the provider
	// says when the event happened, TimeCreated when all that is known is when
	// the record was written.
	TimeSource string

	// Fields is what the rules see.
	Fields map[string]string
	// Skipped names fields that could not be rendered or used at all. The
	// record is kept: one field of an unusual type is a reason to flag that
	// field, not to throw away evidence. Empty on every record of the pinned
	// corpus.
	Skipped []string
	// Blocks names the parts of the record other than System and EventData
	// that values were read from, as "UserData/LogFileCleared". Most records
	// have none.
	Blocks []string
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
			// An element with attributes, such as Provider or Execution, and
			// sometimes one that has both a value and attributes, such as
			// EventID when the provider sets Qualifiers.
			if text, ok := elementText(v); ok {
				if s, err := scalar(text); err == nil {
					f.Fields[name] = s
				}
			}
			for an, av := range elementAttributes(v) {
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
		default:
			s, err := scalar(raw)
			if err != nil {
				f.Skipped = append(f.Skipped, name)
				continue
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
		if err := f.addData(n, "EventData", data); err != nil {
			return Flat{}, err
		}
	default:
		// Not a mapping. Keep it whole rather than guess at its structure.
		raw, err := json.Marshal(data)
		if err != nil {
			return Flat{}, fmt.Errorf("EventData: %w", err)
		}
		f.Fields["EventData"] = string(raw)
	}

	// Windows does not put a provider's own values only in EventData. A handful
	// of events — the two that say the log was cleared among them — write them
	// in a UserData block instead, wrapped in one named element:
	//
	//	{"UserData": {"LogFileCleared": {"SubjectUserName": "bob", ...}}}
	//
	// Reading only System and EventData left those records with no actor at all,
	// which for "somebody cleared the audit log" is the one thing worth knowing.
	// So any other block the record carries is flattened the same way, and its
	// name is recorded: a block nobody expected should show up in the audit
	// rather than be dropped on the assumption that it is not interesting.
	for name, raw := range ev {
		switch name {
		case "System", "EventData":
			continue
		case "#attributes":
			// The Event element's own XML attributes: the schema namespace, and
			// nothing a detection or a report has any use for.
			continue
		}
		block, ok := raw.(map[string]any)
		if !ok {
			f.Skipped = append(f.Skipped, name)
			continue
		}
		for inner, content := range block {
			// A namespace declaration is XML plumbing. One record in the pinned
			// corpus produced a field called xmlns:auto-ns2 holding a schema
			// URL, which is the kind of thing that ends up in a report because
			// nobody looked at the output.
			if strings.HasPrefix(inner, "xmlns") {
				continue
			}
			f.Blocks = append(f.Blocks, name+"/"+inner)
			fields, ok := content.(map[string]any)
			if !ok {
				// A value directly under the block rather than an element of
				// its own. Rendered under the inner name, which is what the
				// provider called it.
				res, err := n.Render(f.Producer, inner, content)
				if err != nil {
					return Flat{}, fmt.Errorf("%s.%s: %w", name, inner, err)
				}
				f.set(inner, res.Text)
				continue
			}
			if err := f.addData(n, name+"."+inner, fields); err != nil {
				return Flat{}, err
			}
		}
	}
	sort.Strings(f.Blocks)

	f.Channel = f.Fields["Channel"]
	f.Computer = f.Fields["Computer"]
	if id, err := strconv.Atoi(f.Fields["EventID"]); err == nil {
		f.EventID = id
	}
	if ts := f.Fields["SystemTime"]; ts != "" {
		t, err := parseSystemTime(ts)
		if err != nil {
			return Flat{}, err
		}
		f.Time = t
		f.TimeSource = "TimeCreated"
	}
	// A provider that states when the event happened is believed over the
	// moment its record was written. Sysmon writes both, and in this corpus
	// they differ by up to 41 milliseconds — enough to put two events in the
	// wrong order, which is enough to change the story a timeline tells.
	//
	// The key is matched exactly. Sysmon also writes CreationUtcTime and
	// PreviousCreationUtcTime, and those are properties of a file, not of the
	// event: taking either for the event time would move an event to whenever
	// somebody last touched the file it mentions.
	if ts := f.Fields["UtcTime"]; ts != "" {
		t, err := parseUtcTime(ts)
		if err != nil {
			f.Skipped = append(f.Skipped, "UtcTime")
		} else {
			f.Time = t
			f.TimeSource = "UtcTime"
		}
	}
	return f, nil
}

// Unavailable reports whether a value is one of the ways Windows writes "there
// is nothing here".
//
// These are values in the file, so they stay in Fields exactly as written: a
// rule has to see what the provider wrote, and deciding otherwise here would
// make detection depend on this function's taste. What they are not is
// information, so nothing built for a person to read should present them as
// one. An entity named "-", or a report line reading Company: ?, is noise
// dressed up as evidence.
//
// Every spelling below was taken out of the corpus rather than guessed:
//
//	""            RuleName, on a Sysmon 10
//	"-"           RuleName on a Sysmon 11, and most absent Security fields
//	"?"           Company, Description, FileVersion and Product on a Sysmon 1,
//	              where the binary carried no version resource
//	"Binary Data" Details on a Sysmon 13, where the written value was too large
//	              for the provider to include
//	"%%1793"      DisplayName, HomeDirectory, HomePath, ScriptPath, ProfilePath,
//	              UserWorkstations and LogonHours on an account event, where it
//	              is a reference into the provider's message table rather than
//	              plain text. Windows itself renders it as "<value not set>",
//	              confirmed by having a real installation render a 4720 out of
//	              this corpus: all seven of those fields carried %%1793 and all
//	              seven came out as "value not set". It is the only code those
//	              fields carry anywhere in the corpus.
//
// Two codes that look like it are deliberately not here. %%1794 is "<never>",
// which is a fact about an account and not the absence of one — an account that
// never expires is something a report should say. And %%1792 is "<value
// changed, but not displayed>", which is Windows stating that there is a value
// and declining to show it; treating that as nothing would hide the one thing
// it says.
func Unavailable(s string) bool {
	switch strings.TrimSpace(s) {
	case "", "-", "?", "Binary Data", "%%1793":
		return true
	}
	return false
}

// addData renders one block of the provider's own values into the flat view.
// where names the block for error messages, so that a failure says which part
// of the record it came from.
func (f *Flat) addData(n *normalise.Normaliser, where string, data map[string]any) error {
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
			return fmt.Errorf("%s.%s: %w", where, name, err)
		}
		f.set(name, res.Text)
	}
	return nil
}

// set records a field, keeping whatever it displaced. A name that exists twice
// in one record is rare — one in the whole pinned corpus — but it was a value
// in the evidence, and silently losing it is not an option.
func (f *Flat) set(name, text string) {
	if old, clash := f.Fields[name]; clash {
		if f.Shadowed == nil {
			f.Shadowed = map[string]string{}
		}
		f.Shadowed[name] = old
	}
	f.Fields[name] = text
}

// scalar renders a System value. These are plain types: Windows does not put
// provider-specific encodings in this block, so there is nothing to restore.
//
// The fallback uses reflection rather than widening the type switch, and that
// is not a stylistic choice. A parser is free to return a named type — the EVTX
// library used here declares `type HexInt uint64` and hands it back for fields
// such as Keywords — and in Go a `case uint64:` does not match it. A record
// full of named integers would fall through to the error, every record in the
// file would be counted unreadable, and nothing would say why. That happened.
func scalar(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "", nil
	case string:
		return val, nil
	case bool:
		return strconv.FormatBool(val), nil
	case json.Number:
		return val.String(), nil
	}

	// Binary blobs — a security descriptor, a token, a hash — arrive as bytes.
	// Windows writes them as hexadecimal in its own XML rendering, so that is
	// what they are turned back into. Without this, 413 records in the pinned
	// corpus were unreadable because one field of one provider was a []byte.
	if b, ok := v.([]byte); ok {
		return strings.ToUpper(hex.EncodeToString(b)), nil
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
		return strings.ToUpper(hex.EncodeToString(rv.Bytes())), nil
	}
	switch rv.Kind() {
	case reflect.String:
		return rv.String(), nil
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if f == math.Trunc(f) && math.Abs(f) <= 1<<53 {
			return strconv.FormatInt(int64(f), 10), nil
		}
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("unexpected value of type %T", v)
}

func attribute(block map[string]any, element, name string) string {
	e, ok := block[element].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := elementAttributes(e)[name].(string)
	return s
}

// The two parsers this project has met disagree about how to write an XML
// element that carries both a value and attributes.
//
// One keeps the XML vocabulary: {"#text": 3001, "#attributes": {"Qualifiers": 16384}}.
// The other flattens the attributes into siblings of a key called Value:
// {"Value": 3001, "Qualifiers": 16384}.
//
// Neither is wrong, and which one shows up is a property of the library rather
// than of the evidence — the same lesson as an access mask arriving as a number
// instead of as text, one level up. Both are accepted here, because the
// alternative is a reader that works until somebody changes a dependency.
func elementText(e map[string]any) (any, bool) {
	if v, ok := e["#text"]; ok {
		return v, true
	}
	if v, ok := e["Value"]; ok {
		return v, true
	}
	return nil, false
}

func elementAttributes(e map[string]any) map[string]any {
	if attrs, ok := e["#attributes"].(map[string]any); ok {
		return attrs
	}
	// The flattened shape: everything that is not the element's own value.
	out := make(map[string]any, len(e))
	for k, v := range e {
		if k == "Value" || k == "#text" {
			continue
		}
		out[k] = v
	}
	return out
}

// parseSystemTime accepts the two spellings of the same instant that the
// parsers produce: the timestamp Windows writes, and seconds since the Unix
// epoch, which is what one library hands back after decoding it.
func parseSystemTime(ts string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC(), nil
	}
	if secs, err := strconv.ParseFloat(ts, 64); err == nil {
		whole, frac := math.Modf(secs)
		return time.Unix(int64(whole), int64(frac*float64(time.Second))).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("SystemTime %q is neither a timestamp nor a number of seconds", ts)
}

// parseUtcTime reads the timestamp a provider writes in its own fields. There
// is no zone in the text because the field name is the zone: Sysmon writes UTC
// and says so in the name. The fractional part is optional in the layout, so a
// record written to the second parses as well as one written to the
// millisecond.
func parseUtcTime(ts string) (time.Time, error) {
	t, err := time.Parse("2006-01-02 15:04:05.999999999", ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("UtcTime %q is not a timestamp", ts)
	}
	return t.UTC(), nil
}
