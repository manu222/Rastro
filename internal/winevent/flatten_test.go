package winevent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/manu222/rastro/internal/normalise"
)

// Every record under testdata/ was taken out of the pinned corpus, not written
// by hand. A fixture somebody invented proves that the code handles what its
// author imagined; these prove it handles what Windows actually writes.

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are kept as json.Number so that a large integer is not rounded
	// on its way through a float64 — the same reason the normaliser refuses
	// imprecise floats.
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return rec
}

func TestSysmonProcessCreation(t *testing.T) {
	f, err := Flatten(load(t, "sysmon_process_creation"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}

	// The two blocks end up in one namespace, which is what a rule assumes.
	for field, want := range map[string]string{
		"EventID":       "1",
		"Channel":       "Microsoft-Windows-Sysmon/Operational",
		"Computer":      "IEWIN7",
		"Provider_Name": "Microsoft-Windows-Sysmon",
	} {
		if got := f.Fields[field]; got != want {
			t.Errorf("%s: want %q, got %q", field, want, got)
		}
	}
	if f.Fields["Image"] == "" || f.Fields["CommandLine"] == "" {
		t.Errorf("EventData did not reach the flat view: %v", f.Fields)
	}
	if f.EventID != 1 {
		t.Errorf("EventID not parsed: %d", f.EventID)
	}
	if f.Time.IsZero() {
		t.Error("the record has a SystemTime and the event has no time")
	}
	if f.Time.Year() < 2015 || f.Time.Year() > 2030 {
		t.Errorf("implausible time parsed: %s", f.Time)
	}
}

// 378 records in the pinned corpus write EventID as an element with attributes
// rather than as a bare number. Taken literally that turns EventID into a
// structure, and every rule matching on it stops working — quietly, because a
// rule that matches nothing looks exactly like a rule with nothing to match.
func TestEventIDWrittenAsAnObject(t *testing.T) {
	f, err := Flatten(load(t, "eventid_as_object"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["EventID"] != "3001" {
		t.Errorf("EventID: want 3001, got %q", f.Fields["EventID"])
	}
	if f.EventID != 3001 {
		t.Errorf("EventID not parsed: %d", f.EventID)
	}
	// The attribute that came with it is kept rather than thrown away.
	if f.Fields["EventID_Qualifiers"] != "16384" {
		t.Errorf("the Qualifiers attribute was lost: %v", f.Fields)
	}
	// This record also carries attributes on EventData itself.
	if f.Fields["EventData_Name"] != "EVENT_PROCESSTERMINATION_CROSSPROCESS" {
		t.Errorf("EventData attributes were lost: %v", f.Fields)
	}
}

// Sysmon's own service state record has a Version in both blocks: the schema
// version of the event, and the version of Sysmon. One name, two meanings.
func TestNameCollisionKeepsBothValues(t *testing.T) {
	f, err := Flatten(load(t, "version_collision"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["Version"] != "9.01" {
		t.Errorf("EventData should win a collision: want 9.01, got %q", f.Fields["Version"])
	}
	if f.Shadowed["Version"] != "3" {
		t.Errorf("the displaced System value was dropped: %v", f.Shadowed)
	}
}

// Absent is not empty. A provider that writes no Channel must not come out of
// here with Channel set to "", because a rule testing for the field would then
// be comparing against something that was never recorded.
func TestMissingChannelStaysMissing(t *testing.T) {
	f, err := Flatten(load(t, "rpc_without_channel"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, present := f.Fields["Channel"]; present {
		t.Errorf("a Channel was produced for a record that has none: %q", f.Fields["Channel"])
	}
	// This provider registers no name, only a GUID, and that is then what
	// identifies it. Leaving the producer empty would merge it with every other
	// nameless source.
	if f.Producer != "{68fdd900-4a3e-11d1-84f4-0000f80464e3}" {
		t.Errorf("a provider known only by GUID was not identified: %q", f.Producer)
	}
}

// The DCSync rule reads Properties and SubjectUserName off a 4662. If either
// fails to arrive, rule 9 stops firing and its manifest goes red — this test
// says so three layers earlier, where the cause is obvious.
func TestSecurityRecordCarriesTheFieldsRule9Needs(t *testing.T) {
	f, err := Flatten(load(t, "security_4662"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.EventID != 4662 {
		t.Fatalf("EventID: %d", f.EventID)
	}
	if f.Fields["Properties"] == "" {
		t.Error("Properties is empty")
	}
	if f.Fields["SubjectUserName"] == "" {
		t.Error("SubjectUserName is empty")
	}
}

// Nothing in the corpus should reach the flattener as an undeclared, reshaped
// field without that being noticed. This is the audit in miniature: the real
// one runs over all 132 files once the reader exists.
func TestFixturesRaiseNoUndeclaredFields(t *testing.T) {
	n := normalise.Default()
	for _, name := range []string{
		"sysmon_process_creation", "version_collision", "security_4662",
	} {
		if _, err := Flatten(load(t, name), n); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if gaps := n.Gaps(); len(gaps) != 0 {
		t.Errorf("fields arrived in a shape nobody declared: %+v", gaps)
	}
}

// The Go EVTX parser this project uses does not produce the shape the fixtures
// above were captured in. It writes an element's own value under the key Value
// and lifts the attributes up beside it, and it decodes SystemTime into
// seconds since the Unix epoch rather than leaving the timestamp as text.
//
// This record is built to that shape rather than captured, because that parser
// cannot be run where these tests were written. It is derived from the
// library's own expansion code, and the first run of the reader against a real
// file is what confirms it — if this test is passing and the reader still
// produces nothing, this fixture is the first place to look.
func TestGoParserShape(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":      map[string]any{"Name": "Microsoft-Windows-Sysmon", "Guid": "{5770385f}"},
				"EventID":       map[string]any{"Qualifiers": int64(0), "Value": int64(10)},
				"Channel":       "Microsoft-Windows-Sysmon/Operational",
				"Computer":      "MSEDGEWIN10",
				"EventRecordID": int64(306346),
				"TimeCreated":   map[string]any{"SystemTime": 1557670683.5895078},
				"Execution":     map[string]any{"ProcessID": int64(2036), "ThreadID": int64(296)},
			},
			"EventData": map[string]any{
				"SourceImage":   `C:\Users\Public\a.exe`,
				"TargetImage":   `C:\Windows\system32\lsass.exe`,
				"GrantedAccess": uint32(4112),
			},
		},
	}

	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.EventID != 10 {
		t.Errorf("EventID from the Value key: want 10, got %d", f.EventID)
	}
	if f.Producer != "Microsoft-Windows-Sysmon" {
		t.Errorf("provider from a flattened attribute: %q", f.Producer)
	}
	if f.Fields["ExecutionProcessID"] != "2036" {
		t.Errorf("attribute alias missing: %v", f.Fields)
	}
	// The finding from the feasibility probe, now end to end: a mask that
	// arrives as a number comes out as the text rule 1 matches against.
	if f.Fields["GrantedAccess"] != "0x1010" {
		t.Errorf("GrantedAccess: want 0x1010, got %q", f.Fields["GrantedAccess"])
	}
	if f.Time.IsZero() || f.Time.Year() != 2019 {
		t.Errorf("epoch seconds not decoded: %s", f.Time)
	}
}

// HexInt stands in for the named types a parser is free to return. The EVTX
// library declares `type HexInt uint64` and hands it back for fields such as
// Keywords.
type HexInt uint64

// A type switch on uint64 does not match a named type whose underlying type is
// uint64. Getting this wrong made every record in the pinned corpus unreadable,
// with nothing in the output to say why, so it gets a test of its own.
func TestNamedIntegerTypesAreNotRejected(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":      map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":       map[string]any{"Value": HexInt(1)},
				"Keywords":      HexInt(0x8000000000000000),
				"EventRecordID": HexInt(42),
				"Computer":      "MSEDGEWIN10",
			},
			"EventData": map[string]any{
				"GrantedAccess": HexInt(4112),
			},
		},
	}
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatalf("a named integer type made the whole record unreadable: %v", err)
	}
	if f.EventID != 1 {
		t.Errorf("EventID: %d", f.EventID)
	}
	if f.Fields["Keywords"] != "9223372036854775808" {
		t.Errorf("Keywords: %q", f.Fields["Keywords"])
	}
	if f.Fields["GrantedAccess"] != "0x1010" {
		t.Errorf("GrantedAccess through a named type: %q", f.Fields["GrantedAccess"])
	}
}
