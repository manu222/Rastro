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
