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

	fromRust, err := n.Render(sysmon, 0, "GrantedAccess", "0x1010")
	if err != nil {
		t.Fatalf("string form rejected: %v", err)
	}
	fromGo, err := n.Render(sysmon, 0, "GrantedAccess", uint32(4112))
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
	got, err := n.Render(sysmon, 0, "ProcessId", "0x1358")
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
	sys, _ := n.Render(sysmon, 0, "ProcessId", int64(640))
	sec, _ := n.Render("Microsoft-Windows-Security-Auditing", 0, "ProcessID", int64(812))
	if sys.Text != "640" || sec.Text != "812" {
		t.Errorf("decimal identifiers rendered wrong: %q %q", sys.Text, sec.Text)
	}
}

// 18446744073709551615 is in the corpus. It is the largest unsigned 64-bit
// integer, and it does not survive a float64.
func TestLargestUnsignedValueIsNotCorrupted(t *testing.T) {
	const want = "18446744073709551615"
	n := Default()

	got, err := n.Render("Microsoft-Windows-Bits-Client", 0, "bandwidthLimit", uint64(1<<64-1))
	if err != nil {
		t.Fatalf("a uint64 was rejected: %v", err)
	}
	if got.Text != want {
		t.Errorf("want %s, got %s", want, got.Text)
	}

	// Decoded with json.Number, as a careful JSON reader would.
	got, err = n.Render("Microsoft-Windows-Bits-Client", 0, "bandwidthLimit", json.Number(want))
	if err != nil {
		t.Fatalf("json.Number was rejected: %v", err)
	}
	if got.Text != want {
		t.Errorf("want %s, got %s", want, got.Text)
	}
}

// A value that cannot be carried exactly is dropped and recorded, not rounded
// and not fatal. Two properties matter here and they pull in opposite
// directions: no wrong number ever reaches a report, and no record is lost
// because one of its fields was awkward.
func TestFloatThatCannotBeExactIsDroppedAndRecorded(t *testing.T) {
	n := Default()

	got, err := n.Render("Microsoft-Windows-Bits-Client", 0, "bandwidthLimit", float64(1<<64-1))
	if err != nil {
		t.Fatalf("an imprecise value killed the record: %v", err)
	}
	if got.Text != "" {
		t.Errorf("an approximate number was reported: %q (the true value is 18446744073709551615)", got.Text)
	}
	if len(gapsFor(n, "bandwidthLimit")) != 1 {
		t.Errorf("the loss was not recorded: %+v", n.Gaps())
	}

	got, err = n.Render(sysmon, 0, "SourcePort", float64(49158))
	if err != nil || got.Text != "49158" {
		t.Errorf("a float64 small enough to be exact was mishandled: %q %v", got.Text, err)
	}
}

// A number with decimals is not a number that lost something. The corpus has
// fileTime = 1290255420.401, a file time with milliseconds, and an earlier
// version of this package threw it away because the float check asked the wrong
// question: it tested for decimals when what matters is precision.
func TestNumberWithDecimalsIsKept(t *testing.T) {
	n := Default()

	got, err := n.Render("Microsoft-Windows-Bits-Client", 0, "fileTime", float64(1290255420.401))
	if err != nil {
		t.Fatalf("a legitimate number was rejected: %v", err)
	}
	if got.Text != "1290255420.401" {
		t.Errorf("want 1290255420.401, got %q", got.Text)
	}

	// Through json.Number the digits never see a float64, so what comes out is
	// exactly what the file said — including trailing precision a float64 would
	// have rewritten.
	got, err = n.Render("Microsoft-Windows-Bits-Client", 0, "fileTime", json.Number("1557670683.5895078"))
	if err != nil {
		t.Fatalf("json.Number with decimals was rejected: %v", err)
	}
	if got.Text != "1557670683.5895078" {
		t.Errorf("the literal was not preserved: %q", got.Text)
	}

	// Undeclared, so it is still reported — but as a shape, not as a loss.
	gaps := gapsFor(n, "fileTime")
	if len(gaps) != 1 {
		t.Fatalf("an undeclared real was not recorded: %+v", n.Gaps())
	}
	if gaps[0].Shape != "real" {
		t.Errorf("recorded under the wrong shape: %+v", gaps[0])
	}
}

// The distinction the fix above rests on: decimals are fine, magnitude is not.
func TestLargeIntegralFloatIsStillRefused(t *testing.T) {
	n := Default()
	got, err := n.Render("Microsoft-Windows-Bits-Client", 0, "bandwidthLimit", float64(1<<63))
	if err != nil {
		t.Fatalf("an imprecise value killed the record: %v", err)
	}
	if got.Text != "" {
		t.Errorf("a number that cannot be exact was reported anyway: %q", got.Text)
	}
}

// A field declared as real raises nothing: that is the whole point of declaring
// it.
func TestDeclaredRealIsNotAGap(t *testing.T) {
	n := New(&Table{
		Producer: "Microsoft-Windows-Bits-Client",
		Fields:   map[string]Form{"fileTime": FormReal},
	})
	got, err := n.Render("Microsoft-Windows-Bits-Client", 0, "fileTime", float64(1290255420.401))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Declared {
		t.Error("a declared field was reported as undeclared")
	}
	if len(n.Gaps()) != 0 {
		t.Errorf("a declared real was reported as a gap: %+v", n.Gaps())
	}
}

// Several Data elements under one name arrive as a list. They are joined, not
// JSON-encoded: a rule looking for a Windows path inside the value would stop
// matching the moment backslashes were escaped.
func TestListOfValuesIsJoinedWithoutEscaping(t *testing.T) {
	n := Default()
	got, err := n.Render("MSSQLSERVER", 0, "Data", []string{"sa", `Reason: C:\Windows\x.exe`})
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "sa\nReason: C:\\Windows\\x.exe" {
		t.Errorf("list rendering: %q", got.Text)
	}
}

// A message table reference is a label, not a quantity.
func TestMessageReferenceIsNotTurnedIntoArithmetic(t *testing.T) {
	n := Default()
	got, _ := n.Render("Microsoft-Windows-Security-Auditing", 0, "ImpersonationLevel", "%%1833")
	if got.Text != "%%1833" {
		t.Errorf("a message reference was rewritten: %q", got.Text)
	}
	// Arriving as a bare number contradicts the declaration, so it is recorded.
	if _, err := n.Render("Microsoft-Windows-Security-Auditing", 0, "ImpersonationLevel", int64(3)); err != nil {
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
	if _, err := n.Render(sysmon, 0, "SomeFieldNobodyDeclared", int64(7)); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Render(sysmon, 0, "SomeFieldNobodyDeclared", int64(9)); err != nil {
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
	if _, err := n.Render(sysmon, 0, "SomethingElse", "a value"); err != nil {
		t.Fatal(err)
	}
	if len(n.Gaps()) != 0 {
		t.Errorf("undeclared text was reported as a gap: %+v", n.Gaps())
	}
}

func TestNestedValueIsKeptAsJSON(t *testing.T) {
	n := Default()
	got, err := n.Render(sysmon, 0, "Data", map[string]any{"#text": "sa"})
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

// The same field name, the same provider, two bases. 4688 and 5158 both sit
// in the Security channel of LSASS_campaign_01, with ProcessId 0x11c0 on one
// and 1048 on the other.
func TestOneEventCanWriteAFieldDifferentlyFromItsProvider(t *testing.T) {
	n := Default()
	const sec = "Microsoft-Windows-Security-Auditing"
	for _, c := range []struct {
		id   int
		want string
		form Form
	}{
		{4688, "0x418", FormHex},
		{5158, "1048", FormDecimal},
	} {
		res, err := n.Render(sec, c.id, "ProcessId", int64(1048))
		if err != nil {
			t.Fatal(err)
		}
		if res.Text != c.want {
			t.Errorf("%d: rendered %q, want %q", c.id, res.Text, c.want)
		}
		if got := n.Form(sec, c.id, "ProcessId"); got != c.form {
			t.Errorf("%d: declared %s, want %s", c.id, got, c.form)
		}
	}
}
