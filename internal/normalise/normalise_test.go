package normalise

import (
	"encoding/json"
	"testing"
)

const sysmon = "Microsoft-Windows-Sysmon"

// The finding that started all of this: one parser returns an access mask as
// text, another as a number, and a rule written against the text stops matching
// without saying so.
func TestAccessMaskSurvivesEitherParser(t *testing.T) {
	n := Default()

	fromRust, err := n.Render(sysmon, "GrantedAccess", "0x1010")
	if err != nil {
		t.Fatalf("string form rejected: %v", err)
	}
	fromGo, err := n.Render(sysmon, "GrantedAccess", uint32(4112))
	if err != nil {
		t.Fatalf("numeric form rejected: %v", err)
	}
	if fromRust.Text != fromGo.Text {
		t.Errorf("the same value renders differently depending on the parser: %q and %q",
			fromRust.Text, fromGo.Text)
	}
	if fromRust.Text != "0x1010" {
		t.Errorf("want 0x1010, got %q", fromRust.Text)
	}
	if !fromGo.Restored {
		t.Error("putting a number back into hexadecimal was not reported as restoring anything")
	}
}

// A provider's own text is never second-guessed, whatever the table says.
func TestTextIsLeftAlone(t *testing.T) {
	n := Default()
	got, err := n.Render(sysmon, "ProcessId", "0x1358")
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "0x1358" {
		t.Errorf("a value the provider wrote was rewritten: %q", got.Text)
	}
	if got.Restored {
		t.Error("a value that needed no work was reported as restored")
	}
}

// Two providers, the same field name, two correct answers. This is why the
// tables are per provider and not one global map.
func TestProvidersDisagreeAndBothAreRight(t *testing.T) {
	n := Default()
	sys, _ := n.Render(sysmon, "ProcessId", int64(640))
	sec, _ := n.Render("Microsoft-Windows-Security-Auditing", "ProcessID", int64(812))
	if sys.Text != "640" || sec.Text != "812" {
		t.Errorf("decimal identifiers rendered wrong: %q %q", sys.Text, sec.Text)
	}
}

// 18446744073709551615 is in the corpus. It is the largest unsigned 64-bit
// integer, and it does not survive a float64.
func TestLargestUnsignedValueIsNotCorrupted(t *testing.T) {
	const want = "18446744073709551615"
	n := Default()

	got, err := n.Render("Microsoft-Windows-Bits-Client", "bandwidthLimit", uint64(1<<64-1))
	if err != nil {
		t.Fatalf("a uint64 was rejected: %v", err)
	}
	if got.Text != want {
		t.Errorf("want %s, got %s", want, got.Text)
	}

	// Decoded with json.Number, as a careful JSON reader would.
	got, err = n.Render("Microsoft-Windows-Bits-Client", "bandwidthLimit", json.Number(want))
	if err != nil {
		t.Fatalf("json.Number was rejected: %v", err)
	}
	if got.Text != want {
		t.Errorf("want %s, got %s", want, got.Text)
	}
}

// The same value as a float64 must be refused rather than rounded. A wrong
// number in a report is worse than a missing one.
func TestFloatThatCannotBeExactIsRefused(t *testing.T) {
	n := Default()
	if _, err := n.Render("Microsoft-Windows-Bits-Client", "bandwidthLimit", float64(1<<64-1)); err == nil {
		t.Error("a float64 too large to be exact was accepted; it would have reported 18446744073709551616")
	}
	if _, err := n.Render(sysmon, "SourcePort", float64(49158)); err != nil {
		t.Errorf("a float64 small enough to be exact was refused: %v", err)
	}
}

// A message table reference is a label, not a quantity.
func TestMessageReferenceIsNotTurnedIntoArithmetic(t *testing.T) {
	n := Default()
	got, _ := n.Render("Microsoft-Windows-Security-Auditing", "ImpersonationLevel", "%%1833")
	if got.Text != "%%1833" {
		t.Errorf("a message reference was rewritten: %q", got.Text)
	}
	// Arriving as a bare number contradicts the declaration, so it is recorded.
	if _, err := n.Render("Microsoft-Windows-Security-Auditing", "ImpersonationLevel", int64(3)); err != nil {
		t.Fatal(err)
	}
	gaps := gapsFor(n, "ImpersonationLevel")
	if len(gaps) != 1 {
		t.Fatalf("the contradiction was not recorded: %+v", n.Gaps())
	}
	if gaps[0].Declared != FormMessageRef {
		t.Errorf("the recorded gap lost the declaration it contradicts: %+v", gaps[0])
	}
}

// The gap that the whole design admits it cannot close: a field nobody
// declared. It must not be silent.
func TestUndeclaredFieldIsRecorded(t *testing.T) {
	n := Default()
	if _, err := n.Render(sysmon, "SomeFieldNobodyDeclared", int64(7)); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Render(sysmon, "SomeFieldNobodyDeclared", int64(9)); err != nil {
		t.Fatal(err)
	}
	gaps := gapsFor(n, "SomeFieldNobodyDeclared")
	if len(gaps) != 1 {
		t.Fatalf("an undeclared numeric field went unnoticed: %+v", n.Gaps())
	}
	if gaps[0].Count != 2 {
		t.Errorf("want 2 sightings, got %d", gaps[0].Count)
	}
	if gaps[0].Declared != FormUnset {
		t.Errorf("an undeclared field was recorded as declared: %+v", gaps[0])
	}
}

// Text never raises a gap, however undeclared: text is what the provider wrote,
// and nothing was reshaped. Otherwise the audit would drown in noise and stop
// being read.
func TestUndeclaredTextIsNotAGap(t *testing.T) {
	n := Default()
	if _, err := n.Render(sysmon, "SomethingElse", "a value"); err != nil {
		t.Fatal(err)
	}
	if len(n.Gaps()) != 0 {
		t.Errorf("undeclared text was reported as a gap: %+v", n.Gaps())
	}
}

func TestNestedValueIsKeptAsJSON(t *testing.T) {
	n := Default()
	got, err := n.Render(sysmon, "Data", map[string]any{"#text": "sa"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != `{"#text":"sa"}` {
		t.Errorf("nested value lost: %q", got.Text)
	}
}

func gapsFor(n *Normaliser, field string) []Gap {
	var out []Gap
	for _, g := range n.Gaps() {
		if g.Field == field {
			out = append(out, g)
		}
	}
	return out
}
