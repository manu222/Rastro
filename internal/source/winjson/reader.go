// Package winjson reads Windows event records that have already been through a
// log shipper: one JSON object per line, with the record's fields flattened
// into a single namespace.
//
// This is the shape most Windows evidence is in by the time anyone looks at it.
// An .evtx file is what the machine wrote; what arrives in an investigation is
// usually an export from whatever collected it, and the collector has already
// walked the XML, resolved the types and written the result out as text. The
// readers for the two are different jobs. The EVTX reader's problem is a binary
// format and a library that hands back named integers; this one's problem is
// that somebody else has already made every decision the EVTX reader makes, and
// it has to find out whether they made them the same way.
//
// So the fields are not re-rendered here. They arrive as text and the text is
// what the rules see, unchanged. What this reader does instead is check that
// text against the provider tables the other path renders through: when Windows
// writes a logon id as 0x3e7 and a shipper has written 999, every rule
// mentioning that field stops matching, and nothing anywhere says so. That is
// the same failure as an access mask arriving as a number instead of as text,
// one layer removed, and the only place it can be caught is here.
//
// The second thing it has to decide is which time to believe, and that one is
// worth spelling out because this reader answers it differently from the EVTX
// reader. See the comment on timeOf.
package winjson

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/normalise"
	"github.com/manu222/rastro/internal/winevent"
)

// Limits bound what one file is allowed to cost. Evidence is attacker-chosen
// input, and a compressed file is the place where that stops being theoretical:
// a few kilobytes on disk can expand to as much as the machine will give.
type Limits struct {
	MaxRecords int
	MaxBytes   int64
	// MaxExpanded caps how much a compressed file is allowed to become. It has
	// no effect on a plain one.
	MaxExpanded int64
	MaxLine     int
}

// DefaultLimits are generous for real evidence. A day of Sysmon off one busy
// host is a few hundred megabytes of this and entirely ordinary.
func DefaultLimits() Limits {
	return Limits{
		MaxRecords:  50_000_000,
		MaxBytes:    16 << 30,
		MaxExpanded: 64 << 30,
		MaxLine:     4 << 20,
	}
}

// Stats is what the reader can say about a file afterwards.
type Stats struct {
	Records int
	// Unparsed counts lines that are not a JSON object. A text file that is not
	// this format at all produces a count equal to its line count, which is
	// the honest answer and a visible one.
	Unparsed int
	// Unreadable counts objects that parsed and could not be turned into an
	// event, because they carry no event identifier or no provider.
	Unreadable   int
	FirstFailure error
	// Disagreements counts records where the provider's own statement of when
	// the event happened disagrees with the time the record carries by more
	// than a minute. See timeOf: it is not an error, it is a property of the
	// evidence, and it decides what a timeline out of this evidence can claim.
	Disagreements int
	// FirstDisagreement is the first of them, in full, because a count with no
	// example gives whoever reads it nowhere to start.
	FirstDisagreement error
	Stopped           string
}

// Divergence is one field that a shipper wrote in a form the provider itself
// does not use.
type Divergence struct {
	Producer string
	Field    string
	// Declared is the form the provider's table says this field is written in.
	Declared normalise.Form
	// Written is what the shipper actually wrote it as.
	Written string
	// Sample is one value, so the warning can be read without going back to
	// the evidence.
	Sample string
	Count  int
}

// Reader walks one evidence directory's worth of shipped Windows events.
type Reader struct {
	Normaliser *normalise.Normaliser
	Limits     Limits
	// Root is the directory the analysis was given. Paths recorded on events
	// are relative to it, so a report does not carry the directory layout of
	// whoever ran the tool.
	Root string

	mu sync.Mutex
	// divergences is keyed by producer, field and written form: a field only
	// has to be reported once however many million records carry it.
	divergences map[string]*Divergence
}

// New returns a reader with the default tables and limits.
func New(root string) *Reader {
	return &Reader{
		Normaliser:  normalise.Default(),
		Limits:      DefaultLimits(),
		Root:        root,
		divergences: map[string]*Divergence{},
	}
}

// Handles reports whether this reader is the one for a file, by its name. A
// .json or .json.gz in an evidence directory is assumed to be this format;
// a file that turns out to be something else counts every line as unparsed
// rather than producing nothing, which is the failure this project spends its
// time avoiding.
func Handles(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")
}

// ReadFile walks one file, calling emit once per record.
//
// emit returning an error stops the walk and the error is returned as is: that
// is how a consumer says "enough".
func (r *Reader) ReadFile(path string, emit func(*event.Event) error) (Stats, error) {
	var stats Stats

	info, err := os.Stat(path)
	if err != nil {
		return stats, err
	}
	if r.Limits.MaxBytes > 0 && info.Size() > r.Limits.MaxBytes {
		return stats, fmt.Errorf("%s is %d bytes, over the %d byte limit",
			filepath.Base(path), info.Size(), r.Limits.MaxBytes)
	}

	fd, err := os.Open(path)
	if err != nil {
		return stats, err
	}
	defer fd.Close()

	var src io.Reader = fd
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			return stats, fmt.Errorf("%s is not readable as gzip: %w", filepath.Base(path), err)
		}
		defer gz.Close()
		if r.Limits.MaxExpanded > 0 {
			// A bound on what the file is allowed to become, not on what it is.
			// One byte over the limit is read deliberately, so that reaching it
			// can be told from a file that simply ends there.
			src = io.LimitReader(gz, r.Limits.MaxExpanded+1)
		} else {
			src = gz
		}
	}

	rel := path
	if r.Root != "" {
		if p, err := filepath.Rel(r.Root, path); err == nil {
			rel = filepath.ToSlash(p)
		}
	}

	max := r.Limits.MaxLine
	if max <= 0 {
		max = 4 << 20
	}
	scan := bufio.NewScanner(src)
	scan.Buffer(make([]byte, 0, 64<<10), max)

	var read int64
	line := int64(0)
	for scan.Scan() {
		line++
		text := scan.Bytes()
		read += int64(len(text)) + 1
		if r.Limits.MaxExpanded > 0 && read > r.Limits.MaxExpanded {
			stats.Stopped = fmt.Sprintf("expanded past the %d byte limit", r.Limits.MaxExpanded)
			return stats, nil
		}
		if len(strings.TrimSpace(string(text))) == 0 {
			continue
		}
		if r.Limits.MaxRecords > 0 && stats.Records >= r.Limits.MaxRecords {
			stats.Stopped = fmt.Sprintf("record limit of %d reached", r.Limits.MaxRecords)
			return stats, nil
		}

		raw, err := decode(text)
		if err != nil {
			stats.Unparsed++
			if stats.FirstFailure == nil {
				stats.FirstFailure = fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}

		ev, err := r.build(raw, rel, line, &stats)
		if err != nil {
			stats.Unreadable++
			if stats.FirstFailure == nil {
				stats.FirstFailure = fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}
		stats.Records++
		if err := emit(ev); err != nil {
			return stats, err
		}
	}
	if err := scan.Err(); err != nil {
		// A line longer than the buffer stops the scan. It is reported as a stop
		// rather than swallowed, because the rest of the file was not read and a
		// partial read must never be mistaken for a complete one.
		stats.Stopped = fmt.Sprintf("line %d: %v", line+1, err)
		if stats.FirstFailure == nil {
			stats.FirstFailure = fmt.Errorf("%s: %w", rel, err)
		}
		return stats, nil
	}
	return stats, nil
}

// decode reads one line into a map, keeping numbers as the text they were
// written as.
//
// UseNumber is the whole reason this is not a one-liner. Through float64 a
// timestamp written as 1692161622.036086 comes back as 1692161622.0360858, and
// a process id of 9007199254740993 comes back as something else entirely. The
// project has met that bug twice; it is not meeting it a third time.
func decode(line []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("an empty JSON object is not a record")
	}
	return raw, nil
}

// shipperAliases are the names the EVTX path produces for values a shipper
// calls something else.
//
// A rule is written once, against one spelling. The EVTX path emits
// Execution_ProcessID and ExecutionProcessID because that is what Windows'
// own XML holds and what rule authors write; a shipper flattens the same value
// to ProcessID. Without these, half the public corpus would load, run and
// quietly fail to fire on evidence that is in front of it, which is the same
// kind of silence as a rule filtered out by a logsource it does not rely on.
//
// The shipper's own name is kept as well as the alias. Nothing is renamed and
// nothing is removed: a field is added under the spelling the rules use.
var shipperAliases = map[string][]string{
	"SourceName":   {"Provider_Name"},
	"Hostname":     {"Computer"},
	"ProcessID":    {"Execution_ProcessID", "ExecutionProcessID"},
	"ThreadID":     {"Execution_ThreadID", "ExecutionThreadID"},
	"UserID":       {"Security_UserID", "SecurityUserID"},
	"RecordNumber": {"EventRecordID"},
	"TimeCreated":  {"TimeCreated_SystemTime", "SystemTime"},
}

// build turns one decoded line into an event.
func (r *Reader) build(raw map[string]any, path string, line int64, stats *Stats) (*event.Event, error) {
	flat := winevent.Flat{Fields: make(map[string]string, len(raw)+8)}

	for name, value := range raw {
		// The shipper's own bookkeeping. @timestamp is read for the time below
		// and @version, @metadata and the rest say nothing about the event.
		if strings.HasPrefix(name, "@") {
			continue
		}
		text, ok := scalar(value)
		if !ok {
			flat.Skipped = append(flat.Skipped, name)
			continue
		}
		flat.Fields[name] = text
		for _, alias := range shipperAliases[name] {
			if _, taken := flat.Fields[alias]; !taken {
				flat.Fields[alias] = text
			}
		}
	}
	sort.Strings(flat.Skipped)

	flat.Producer = flat.Fields["SourceName"]
	if flat.Producer == "" {
		flat.Producer = flat.Fields["ProviderGuid"]
	}
	if flat.Producer == "" {
		return nil, fmt.Errorf("the record names no provider, so no table can say how its fields are written")
	}
	flat.Channel = flat.Fields["Channel"]
	flat.Computer = flat.Fields["Hostname"]

	id, err := strconv.Atoi(flat.Fields["EventID"])
	if err != nil {
		return nil, fmt.Errorf("EventID %q is not a number", flat.Fields["EventID"])
	}
	flat.EventID = id

	// The forms. This is the audit, and it runs on every record because a
	// shipper that renders one field differently renders it differently
	// everywhere, and the cost of looking is a map lookup per field.
	r.audit(flat.Producer, flat.Fields)

	t, source, disagreement := timeOf(flat.Fields, raw)
	flat.Time = t
	flat.TimeSource = source
	if disagreement != nil {
		stats.Disagreements++
		if stats.FirstDisagreement == nil {
			stats.FirstDisagreement = fmt.Errorf("line %d: %w", line, disagreement)
		}
	}

	e := &event.Event{
		Time:     flat.Time,
		Activity: flat.Fields["EventID"],
		Origin: event.Origin{
			Path:      path,
			Record:    line,
			Producer:  producerOf(flat),
			TimeField: flat.TimeSource,
			Product:   "windows",
			Service:   serviceOf(flat.Channel),
		},
		Raw: event.Fields(flat.Fields),
	}

	if !winevent.Unavailable(flat.Computer) {
		e.Host = event.Seen(flat.Computer)
		e.Add(event.KindHost, "", e.Host)
	}

	winevent.Classify(flat, e)
	return e, nil
}

// timeOf decides which of a record's times is the event's, and this reader
// answers it the opposite way round from the EVTX reader. The reason is
// measurable rather than a matter of taste.
//
// A provider that states when something happened is a better answer than the
// moment its record was written, and on an .evtx file read off the machine the
// two come from the same clock milliseconds apart. That is why the EVTX path
// prefers UtcTime, and it is right there.
//
// Evidence that has been through a shipper is not that. In the compound corpus
// this reader was written for, the difference between the provider's UtcTime
// and the record's own time is exactly 19 hours on seventeen Sysmon event
// types, with the records of each type agreeing with each other to under a
// second — and on event 3, network connection, and event 22, DNS query, it is
// 115 hours. Those two are precisely the event types a network join needs.
//
// So the record's time is used, because it is the one that is internally
// consistent across every event in the file, and a timeline is a statement
// about order. A whole timeline shifted by nineteen hours still says what
// happened before what; one event moved five days out of place does not, and it
// moves the single event somebody would be reading the timeline to find.
//
// The disagreement is not discarded. UtcTime stays in the fields exactly as
// written, so rules see what the provider wrote, and a record whose two times
// are more than a minute apart is counted and the first one kept. Evidence this
// is true of can order events and cannot date them, and the only honest thing
// to do with that is say so in the report rather than pick a winner quietly.
func timeOf(fields map[string]string, raw map[string]any) (time.Time, string, error) {
	var recorded time.Time
	source := ""

	// TimeCreated is the record's own. @timestamp is the shipper's note of when
	// it handled the record, which is the fallback and is named as such, because
	// "when the collector saw it" and "when it happened" are different claims.
	if ts := fields["TimeCreated"]; ts != "" {
		if t, err := parseStamp(ts); err == nil {
			recorded, source = t, "TimeCreated"
		}
	}
	if source == "" {
		if ts, ok := raw["@timestamp"].(string); ok && ts != "" {
			if t, err := parseStamp(ts); err == nil {
				recorded, source = t, "@timestamp"
			}
		}
	}

	// The provider's own statement, kept for the comparison only. The key is
	// matched exactly: Sysmon also writes CreationUtcTime and
	// PreviousCreationUtcTime, and those are properties of a file rather than
	// of the event.
	stated, ok := statedTime(fields["UtcTime"])
	switch {
	case source == "" && ok:
		// No record time at all. The provider's is then the only one there is,
		// and saying where it came from is the point of TimeField.
		return stated, "UtcTime", nil
	case source == "":
		return time.Time{}, "", nil
	case !ok:
		return recorded, source, nil
	}

	if gap := stated.Sub(recorded); gap > time.Minute || gap < -time.Minute {
		return recorded, source, fmt.Errorf(
			"the provider says the event happened at %s and the record is dated %s, %s apart: "+
				"times from this evidence order events and do not date them",
			stated.Format(time.RFC3339), recorded.Format(time.RFC3339), gap.Round(time.Second))
	}
	return recorded, source, nil
}

func statedTime(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05.999999999", ts)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// parseStamp reads the timestamp a shipper writes. The zone is in the text, and
// a record written to the second parses as well as one written to the
// nanosecond.
func parseStamp(ts string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%q is not a timestamp", ts)
}

// audit compares what the shipper wrote against what the provider's table says
// the provider writes.
//
// Only the three forms that break a comparison are checked. A hexadecimal field
// written in base ten, or the other way round, makes every rule that mentions
// it fail to match; a boolean written as T instead of true does the same. The
// rest — text, a message-table reference, a blob — either cannot be checked
// from the text alone or cannot be got wrong in a way that matters.
//
// Case is not a divergence. The matching in this project folds case, so 0x3E7
// and 0x3e7 are the same value to every rule, and reporting it would be noise
// that teaches whoever reads the audit to ignore it.
func (r *Reader) audit(producer string, fields map[string]string) {
	for name, text := range fields {
		declared := r.Normaliser.Form(producer, name)
		switch declared {
		case normalise.FormHex, normalise.FormDecimal, normalise.FormBool:
		default:
			continue
		}
		written, ok := formOf(text)
		if !ok || written == declared {
			continue
		}
		r.note(producer, name, declared, written, text)
	}
}

// formOf reads a value's form off the text, and says so only when the text
// settles it. "0" is a decimal integer and a hexadecimal one and an answer to
// neither question, so it is left alone.
func formOf(text string) (normalise.Form, bool) {
	s := strings.TrimSpace(text)
	if s == "" {
		return normalise.FormUnset, false
	}
	switch strings.ToLower(s) {
	case "true", "false":
		return normalise.FormBool, true
	}
	if len(s) > 2 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		if allHexDigits(s[2:]) {
			return normalise.FormHex, true
		}
		return normalise.FormUnset, false
	}
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || !allDecimalDigits(digits) {
		return normalise.FormUnset, false
	}
	if digits == "0" {
		// Zero is written the same way in both bases, so it proves nothing
		// about which one the shipper used.
		return normalise.FormUnset, false
	}
	return normalise.FormDecimal, true
}

func allDecimalDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func allHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

func (r *Reader) note(producer, field string, declared, written normalise.Form, sample string) {
	key := producer + "\x00" + field + "\x00" + written.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.divergences == nil {
		r.divergences = map[string]*Divergence{}
	}
	if d, ok := r.divergences[key]; ok {
		d.Count++
		return
	}
	r.divergences[key] = &Divergence{
		Producer: producer,
		Field:    field,
		Declared: declared,
		Written:  written.String(),
		Sample:   truncate(sample),
		Count:    1,
	}
}

// Divergences reports the fields this reader found written in a form the
// provider does not use, for the warning that belongs in the report.
func (r *Reader) Divergences() []Divergence {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Divergence, 0, len(r.divergences))
	for _, d := range r.divergences {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Producer != out[j].Producer {
			return out[i].Producer < out[j].Producer
		}
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Written < out[j].Written
	})
	return out
}

// Gaps reports what the tables did not describe. Nothing is rendered on this
// path, so there is nothing to find — the method exists so that a reader of
// this format can stand in for the EVTX one where a caller only needs to walk
// evidence.
func (r *Reader) Gaps() []normalise.Gap { return r.Normaliser.Gaps() }

func truncate(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}

// scalar renders one JSON value as the text a rule will see.
//
// Numbers keep the digits they were written with: decode asked for that and
// throwing it away here would undo it. A nested value is kept as compact JSON,
// because a rule can still match text inside it and the alternative is losing
// evidence to make the map tidier.
func scalar(v any) (string, bool) {
	switch val := v.(type) {
	case nil:
		// Absent is absent. An empty string here would make a rule testing
		// whether the field exists match on nothing.
		return "", false
	case string:
		return val, true
	case json.Number:
		return val.String(), true
	case bool:
		return strconv.FormatBool(val), true
	case map[string]any, []any:
		raw, err := json.Marshal(val)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
	return "", false
}

// producerOf names the source of a record the way an analyst would: the channel
// when it is a name, and the provider otherwise. The same rule as the EVTX
// path, for the same reason — a list of sources headed by a number identifies
// nothing.
func producerOf(flat winevent.Flat) string {
	if flat.Channel != "" && !allDecimalDigits(flat.Channel) {
		return flat.Channel
	}
	return flat.Producer
}

// serviceOf names the channel the way a Sigma rule names it:
// Microsoft-Windows-Sysmon/Operational is "sysmon", Security is "security".
func serviceOf(channel string) string {
	if channel == "" {
		return ""
	}
	if i := strings.LastIndexByte(channel, '/'); i >= 0 {
		channel = channel[:i]
	}
	channel = strings.TrimPrefix(channel, "Microsoft-Windows-")
	return strings.ToLower(channel)
}
