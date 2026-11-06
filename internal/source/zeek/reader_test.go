package zeek

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
)

// Every line below was copied out of the pinned corpus, headers included.
// A log this reader has to understand is one Zeek actually wrote, and the
// header is half the format: it declares the separator, the string for a field
// that is empty and the string for a field that is unset, and those last two
// are different things.

const dnsLog = "#separator \\x09\n" +
	"#set_separator\t,\n" +
	"#empty_field\t(empty)\n" +
	"#unset_field\t-\n" +
	"#path\tdns\n" +
	"#open\t2024-04-12-19-29-12\n" +
	"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n" +
	"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\n" +
	"1521911720.865716\tCqKst53mF3det3eDV9\t10.47.1.100\t41772\t10.0.0.100\t53\tudp\t36329\t0.000870\tise.wrccdc.org\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\tise.wrccdc.cpp.edu,134.71.3.16\t2230.000000,41830.000000\tF\n" +
	"#close\t2024-04-12-19-29-12\n"

func read(t *testing.T, name, body string) ([]*event.Event, Stats) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out []*event.Event
	stats, err := New(dir).ReadFile(path, func(e *event.Event) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, stats
}

func TestARealDnsLog(t *testing.T) {
	events, stats := read(t, "dns.log", dnsLog)
	if stats.Records != 1 || stats.Unparsed != 0 || stats.Malformed != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	e := events[0]

	// The timestamp to the microsecond. Read through a float64 it comes back
	// as something else, which is the error this project keeps meeting.
	if got := e.Time.Format("2006-01-02 15:04:05.000000"); got != "2018-03-24 17:15:20.865716" {
		t.Errorf("time: %s", got)
	}
	// Field names exactly as Zeek writes them, because that is what the rules
	// say: a rule asks for id.resp_p and for Z, and renaming either to
	// something tidier breaks every Zeek rule there is.
	for field, want := range map[string]string{
		"query":      "ise.wrccdc.org",
		"qtype_name": "A",
		"id.resp_p":  "53",
		"Z":          "0",
		"answers":    "ise.wrccdc.cpp.edu,134.71.3.16",
		"rejected":   "F",
	} {
		if got := e.Raw[field]; got != want {
			t.Errorf("%s: want %q, got %q", field, want, got)
		}
	}
	if e.Origin.Product != "zeek" || e.Origin.Service != "dns" {
		t.Errorf("a rule asking for zeek/dns would not see this: %+v", e.Origin)
	}
	if e.Class != event.ClassNetwork || e.Action != "dns query" {
		t.Errorf("class %s action %q", e.Class, e.Action)
	}
}

// The two things a Zeek log says about a missing value, which are not the same
// thing. Windows does not make this distinction and Zeek declares it in the
// header, so throwing it away here would be discarding something the format
// went to the trouble of recording.
func TestUnsetIsAbsentAndEmptyIsPresent(t *testing.T) {
	body := "#separator \\x09\n#unset_field\t-\n#empty_field\t(empty)\n#path\tssl\n" +
		"#fields\tts\tserver_name\tnext_protocol\tcert_chain_fps\n" +
		"1521911720.615923\t-\t(empty)\texample\n"
	events, _ := read(t, "ssl.log", body)
	e := events[0]

	if _, present := e.Raw["server_name"]; present {
		t.Error("an unset field was given a value; a rule asking whether it is absent would be told it is not")
	}
	v, present := e.Raw["next_protocol"]
	if !present || v != "" {
		t.Errorf("an empty field was dropped instead of kept empty: %q present=%v", v, present)
	}
}

// A row that does not line up with its header is skipped and counted.
// Attributing its values to the wrong names would be worse than not reading
// it, and it would be invisible.
func TestARowThatDoesNotLineUpIsRefused(t *testing.T) {
	body := "#separator \\x09\n#unset_field\t-\n#path\tdns\n#fields\tts\tquery\tZ\n" +
		"1521911720.865716\tgood.example\t0\n" +
		"1521911720.865717\ttoo\tmany\tcolumns\n"
	events, stats := read(t, "dns.log", body)

	if stats.Records != 1 || stats.Malformed != 1 {
		t.Errorf("stats: %+v", stats)
	}
	if events[0].Raw["query"] != "good.example" {
		t.Errorf("the good row was read wrong: %v", events[0].Raw)
	}
	if stats.FirstFailure == nil {
		t.Error("a malformed row was counted with no cause recorded")
	}
}

// Rotated logs get concatenated, and the second header has to replace the
// first rather than be ignored. A reader that kept the first set of field
// names would silently attribute every value of the second half to the wrong
// name.
func TestASecondHeaderReplacesTheFirst(t *testing.T) {
	body := "#separator \\x09\n#unset_field\t-\n#path\tdns\n#fields\tts\tquery\n" +
		"1521911720.865716\tfirst.example\n" +
		"#close\t2024-04-12-19-29-12\n" +
		"#separator \\x09\n#unset_field\t-\n#path\tdns\n#fields\tts\tquery\tqtype_name\n" +
		"1521911721.000000\tsecond.example\tAAAA\n"
	events, stats := read(t, "dns.log", body)

	if stats.Records != 2 || stats.Malformed != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	if events[1].Raw["query"] != "second.example" || events[1].Raw["qtype_name"] != "AAAA" {
		t.Errorf("the second block was read with the first block's header: %v", events[1].Raw)
	}
}

// The JSON form has to produce the same fields with the same text as the TSV
// form, or a rule would match one and not the other depending on how the
// network team configured their logging.
func TestTheJSONFormAgreesWithTheTSVForm(t *testing.T) {
	tsv, _ := read(t, "dns.log", dnsLog)
	body := `{"ts":1521911720.865716,"uid":"CqKst53mF3det3eDV9","id.orig_h":"10.47.1.100",` +
		`"id.orig_p":41772,"id.resp_h":"10.0.0.100","id.resp_p":53,"proto":"udp",` +
		`"query":"ise.wrccdc.org","qtype_name":"A","Z":0,"rejected":false,` +
		`"answers":["ise.wrccdc.cpp.edu","134.71.3.16"],"rtt":0.000870}` + "\n"
	js, stats := read(t, "dns.log", body)
	if stats.Records != 1 {
		t.Fatalf("stats: %+v", stats)
	}

	for _, field := range []string{"query", "qtype_name", "Z", "id.resp_p", "answers", "rejected", "uid"} {
		if js[0].Raw[field] != tsv[0].Raw[field] {
			t.Errorf("%s: the two forms disagree: json %q, tsv %q",
				field, js[0].Raw[field], tsv[0].Raw[field])
		}
	}
	if !js[0].Time.Equal(tsv[0].Time) {
		t.Errorf("the two forms disagree about the time: %s and %s", js[0].Time, tsv[0].Time)
	}
}

// A name is a name and an address is an address, and a report that lists
// 10.47.3.200 under domains is wrong in the section somebody reads to decide
// what to block.
func TestAnAddressInTheHostHeaderIsNotADomain(t *testing.T) {
	body := "#separator \\x09\n#unset_field\t-\n#path\thttp\n#fields\tts\thost\tmethod\turi\n" +
		"1521911720.609736\t10.47.3.200\tGET\t/x\n" +
		"1521911721.000000\tevil.example.com\tGET\t/y\n"
	events, _ := read(t, "http.log", body)

	kindOf := func(e *event.Event, role string) event.Kind {
		for _, ent := range e.Entities {
			if ent.Role == role {
				return ent.Kind
			}
		}
		return event.KindUnknown
	}
	if got := kindOf(events[0], "requested"); got != event.KindAddress {
		t.Errorf("an address was recorded as a %s", got)
	}
	if got := kindOf(events[1], "requested"); got != event.KindDomain {
		t.Errorf("a name was recorded as a %s", got)
	}
}

// Every record has to be labelled, or a rule stating a logsource will not see
// it and nothing will say why.
func TestEveryRecordSaysWhatKindOfEvidenceItIs(t *testing.T) {
	for name, service := range map[string]string{
		"dns.log": "dns", "conn.log": "conn", "http.log": "http", "ssl.log": "ssl",
	} {
		body := "#separator \\x09\n#unset_field\t-\n#fields\tts\tx\n1521911720.0\ty\n"
		events, _ := read(t, name, body)
		if len(events) != 1 {
			t.Fatalf("%s: %d events", name, len(events))
		}
		// The service falls back to the file's own name, because the JSON
		// writer produces no #path directive and a log called dns.log is a
		// dns log whatever it says inside.
		if events[0].Origin.Service != service || events[0].Origin.Product != "zeek" {
			t.Errorf("%s: %+v", name, events[0].Origin)
		}
	}
}

// And the whole point: a rule written for Zeek matches a Zeek record, and a
// rule written for something else never sees it.
func TestARuleWrittenForZeekMatchesAZeekRecord(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(rulePath, []byte(`
title: A query for a suspicious name
logsource:
    product: zeek
    service: dns
detection:
    selection:
        query|endswith: '.wrccdc.org'
        qtype_name: 'A'
    condition: selection
level: medium
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sigma.LoadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}

	events, _ := read(t, "dns.log", dnsLog)
	e := events[0]
	if !c.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Categories...) {
		t.Fatal("a Zeek rule did not apply to a Zeek record")
	}
	if !c.Matches(e.Raw) {
		t.Fatalf("the rule did not match: %v", e.Raw)
	}
	hits := c.Explain(e.Raw)
	if len(hits) != 2 {
		t.Errorf("want two reasons, got %+v", hits)
	}

	// And the same record against a rule for another product.
	windows := strings.Replace(string(mustRead(t, rulePath)), "product: zeek", "product: windows", 1)
	winPath := filepath.Join(dir, "win.yml")
	if err := os.WriteFile(winPath, []byte(windows), 0o600); err != nil {
		t.Fatal(err)
	}
	wc, err := sigma.LoadFile(winPath)
	if err != nil {
		t.Fatal(err)
	}
	if wc.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Categories...) {
		t.Error("a Windows rule was offered a Zeek record")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A rule that asks only for category: dns, the way twelve of SigmaHQ's do,
// reaches a dns.log record and matches on query, the name Zeek writes it
// under. And the category is not handed to every log: a conn record has none.
func TestARuleWrittenForTheDnsCategoryMatchesADnsLog(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(rulePath, []byte(`
title: A query by category alone
logsource:
    category: dns
detection:
    selection:
        query|endswith: '.wrccdc.org'
    condition: selection
level: medium
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sigma.LoadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	events, _ := read(t, "dns.log", dnsLog)
	e := events[0]
	if !c.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Categories...) {
		t.Fatalf("a category: dns rule never reaches dns.log: %+v", e.Origin)
	}
	if !c.Matches(e.Raw) {
		t.Fatalf("the rule did not match: %v", e.Raw)
	}

	body := "#separator \\x09\n#unset_field\t-\n#fields\tts\tx\n1521911720.0\ty\n"
	conn, _ := read(t, "conn.log", body)
	if len(conn) != 1 || len(conn[0].Origin.Categories) != 0 {
		t.Errorf("conn.log was given a category: %+v", conn)
	}
}
