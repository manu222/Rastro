package correlate

import (
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/event"
)

// The two records below are the same connection, taken out of the compound
// corpus unchanged. One is a row of Zeek's conn.log and the other is the Sysmon
// 3 the host wrote at the same moment, and between them they say something
// neither says alone: a 7,373-byte response came down from 10.0.5.13 and the
// program that asked for it was Edge, running as stevie.marie.
//
// Note the times. The flow is timestamped 2023-08-16 04:54:08 and the host
// record 2023-08-15 09:54:12, nineteen hours apart, because the host evidence
// went through a shipper that rewrote them. That is why the join is on the
// five-tuple and why none of these tests go anywhere near a time window.

func zeekFlow() *event.Event {
	return &event.Event{
		Class:  event.ClassNetwork,
		Action: "connection",
		Origin: event.Origin{Product: "zeek", Service: "conn", Path: "conn.log", Record: 9},
		Raw: event.Fields{
			"ts": "1692161648.280095", "uid": "CwSLisOv4lXMZlXd3",
			"id.orig_h": "192.168.1.41", "id.orig_p": "51126",
			"id.resp_h": "10.0.5.13", "id.resp_p": "80",
			"proto": "tcp", "service": "-", "duration": "0.100757",
			"orig_bytes": "0", "resp_bytes": "7373", "conn_state": "SHR",
		},
	}
}

func hostConnection() *event.Event {
	e := &event.Event{
		Class:  event.ClassNetwork,
		Action: "network connection",
		Host:   event.Seen("MKT01.pandalab.com"),
		User:   event.Seen(`PANDALAB\stevie.marie`),
		Origin: event.Origin{Product: "windows", Service: "sysmon", Path: "host.json.gz", Record: 1221},
		Process: event.Process{
			Image: event.Seen(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`),
			PID:   event.Seen("7476"),
			GUID:  event.Seen("{81056205-5665-64dc-2704-000000000800}"),
		},
		Raw: event.Fields{
			"EventID": "3", "Protocol": "tcp", "Initiated": "true",
			"SourceIp": "192.168.1.41", "SourcePort": "51126",
			"DestinationIp": "10.0.5.13", "DestinationPort": "80",
			"Image": `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		},
	}
	return e
}

func TestAFlowGainsTheProcessThatOpenedIt(t *testing.T) {
	ix := New()
	ix.Observe(hostConnection())

	c := ix.Connection(zeekFlow())
	if !c.Found() {
		t.Fatalf("the flow was not attributed: %q", c.Unresolved)
	}
	if got := c.Process.Image.Value; !strings.HasSuffix(got, `\msedge.exe`) {
		t.Errorf("attributed to %q", got)
	}
	if c.User.Value != `PANDALAB\stevie.marie` {
		t.Errorf("account: %+v", c.User)
	}
	// Deduced, not observed. The packet carried no process name; this tool put
	// the two records together, and a report has to be able to say so.
	if c.Process.Image.Trusted() {
		t.Error("a process read off a packet capture was marked as observed")
	}
	if c.Process.Image.Why == "" {
		t.Error("a deduced value with no reason is indistinguishable from a guess")
	}
	if !strings.Contains(c.Why, "192.168.1.41:51126 to 10.0.5.13:80 over tcp") {
		t.Errorf("the reason does not name the connection it joined on: %q", c.Why)
	}
}

func TestAHostConnectionGainsWhatCrossedTheWire(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())

	c := ix.Connection(hostConnection())
	if c.Flow == nil {
		t.Fatalf("the host record gained no flow: %q", c.Unresolved)
	}
	if c.Flow.Received != "7373" || c.Flow.Sent != "0" {
		t.Errorf("bytes: sent %q received %q", c.Flow.Sent, c.Flow.Received)
	}
	if c.Flow.State != "SHR" || c.Flow.Duration != "0.100757" {
		t.Errorf("flow: %+v", c.Flow)
	}
	// Zeek's own identifier for the flow. It is carried through because it is
	// what an analyst follows to find the request, the file and the
	// certificate of the same connection in the rest of the network evidence.
	if c.Flow.UID != "CwSLisOv4lXMZlXd3" {
		t.Errorf("uid: %q", c.Flow.UID)
	}
	if c.Flow.Origin.Path != "conn.log" || c.Flow.Origin.Record != 9 {
		t.Errorf("the flow does not point back at its record: %+v", c.Flow.Origin)
	}
}

// Both halves at once, which is how an analysis actually runs: one pass
// observes everything and the second asks.
func TestBothSidesAnswerFromOneIndex(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	ix.Observe(hostConnection())

	if c := ix.Connection(zeekFlow()); c.Process.Image.Value == "" {
		t.Errorf("the flow lost its process: %q", c.Unresolved)
	}
	if c := ix.Connection(hostConnection()); c.Flow == nil {
		t.Errorf("the host record lost its flow: %q", c.Unresolved)
	}
	network, host := ix.Flows()
	if network != 1 || host != 1 {
		t.Errorf("the index holds %d flow(s) and %d host connection(s)", network, host)
	}
}

// A port gets reused. Where two records share a tuple, nothing is attributed:
// the obvious tiebreak is the time, and the time is the one thing these two
// sources demonstrably disagree about.
func TestAReusedPortIsReportedRatherThanGuessed(t *testing.T) {
	ix := New()
	ix.Observe(hostConnection())
	other := hostConnection()
	other.Process.Image = event.Seen(`C:\Windows\System32\curl.exe`)
	other.Raw["Image"] = `C:\Windows\System32\curl.exe`
	other.Origin.Record = 4400
	ix.Observe(other)

	c := ix.Connection(zeekFlow())
	if c.Found() {
		t.Fatalf("one of two candidates was picked: %+v", c.Process)
	}
	if !strings.Contains(c.Unresolved, "2 processes") {
		t.Errorf("the ambiguity does not say how many: %q", c.Unresolved)
	}
	if !strings.Contains(c.Unresolved, "time") {
		t.Errorf("the ambiguity does not say why it cannot be resolved: %q", c.Unresolved)
	}
}

// And the same in the other direction.
func TestTwoFlowsSharingATupleAreReportedRatherThanGuessed(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	second := zeekFlow()
	second.Raw["uid"] = "CsomethingElse"
	second.Origin.Record = 44
	ix.Observe(second)

	c := ix.Connection(hostConnection())
	if c.Flow != nil {
		t.Fatalf("one of two flows was picked: %+v", c.Flow)
	}
	if !strings.Contains(c.Unresolved, "2 flows") {
		t.Errorf("%q", c.Unresolved)
	}
}

// Nothing on the other side is a different answer from an ambiguity, and both
// are different from a blank. A report that shows nothing cannot be read as
// "the tool looked and found nothing" unless the tool says so.
func TestAMissingHalfSaysSo(t *testing.T) {
	ix := New()

	c := ix.Connection(hostConnection())
	if c.Found() || c.Unresolved == "" {
		t.Errorf("%+v", c)
	}
	if !strings.Contains(c.Unresolved, "no flow") {
		t.Errorf("%q", c.Unresolved)
	}

	c = ix.Connection(zeekFlow())
	if c.Found() || !strings.Contains(c.Unresolved, "no host record") {
		t.Errorf("%q", c.Unresolved)
	}
}

// A DNS query carries the same five-tuple as the connection it travelled over
// and is not an account of that connection. Indexing it as one would answer
// "what crossed the wire" with a question rather than with a flow.
func TestADnsRecordIsNotIndexedAsAFlow(t *testing.T) {
	dns := &event.Event{
		Class:  event.ClassNetwork,
		Action: "dns query",
		Origin: event.Origin{Product: "zeek", Service: "dns", Path: "dns.log", Record: 1},
		Raw: event.Fields{
			"uid": "CqKst53mF3det3eDV9", "query": "ise.wrccdc.org",
			"id.orig_h": "192.168.1.41", "id.orig_p": "51126",
			"id.resp_h": "10.0.5.13", "id.resp_p": "80", "proto": "tcp",
		},
	}
	ix := New()
	ix.Observe(dns)

	if network, _ := ix.Flows(); network != 0 {
		t.Errorf("a DNS record was indexed as a flow")
	}
	if c := ix.Connection(hostConnection()); c.Flow != nil {
		t.Errorf("a host record was handed a DNS query as its flow: %+v", c.Flow)
	}

	// It can still ask who opened the connection it travelled over, which is
	// the useful direction and costs nothing.
	ix.Observe(hostConnection())
	if c := ix.Connection(dns); c.Process.Image.Value == "" {
		t.Errorf("the query was not attributed to a process: %q", c.Unresolved)
	}
}

// The tuple is matched as written. Reversing it was measured — it recovers 2 of
// 96 joins in the first campaign and 4 of 861 in the fifth — and the records it
// would recover are the ones where the two sources disagree about which end
// opened the connection, which is a thing to report rather than to smooth over.
func TestAReversedTupleDoesNotMatch(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())

	reversed := hostConnection()
	reversed.Raw["SourceIp"], reversed.Raw["DestinationIp"] = "10.0.5.13", "192.168.1.41"
	reversed.Raw["SourcePort"], reversed.Raw["DestinationPort"] = "80", "51126"

	if c := ix.Connection(reversed); c.Flow != nil {
		t.Error("a tuple matched backwards, which means a connection can be attributed to the wrong end")
	}
}

// A record with no tuple at all gets no answer and no complaint. Most of the
// evidence is not about a connection, and a report full of "the other source
// has nothing to add" on process creations would be noise.
func TestARecordWithNoConnectionIsLeftAlone(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())

	e := &event.Event{
		Class:  event.ClassProcess,
		Action: "process created",
		Raw:    event.Fields{"EventID": "1", "Image": `C:\Windows\System32\cmd.exe`},
	}
	c := ix.Connection(e)
	if c.Found() || c.Unresolved != "" {
		t.Errorf("%+v", c)
	}
}

// A host record that names no program is no use as the answer to "who opened
// this", and recording it would turn a miss into an ambiguity.
func TestAHostRecordWithNoProgramIsNotIndexed(t *testing.T) {
	ix := New()
	nameless := hostConnection()
	nameless.Process = event.Process{}
	delete(nameless.Raw, "Image")
	ix.Observe(nameless)
	ix.Observe(hostConnection())

	c := ix.Connection(zeekFlow())
	if !c.Found() {
		t.Fatalf("a nameless record was counted as a candidate: %q", c.Unresolved)
	}
	if !strings.HasSuffix(c.Process.Image.Value, `\msedge.exe`) {
		t.Errorf("attributed to %q", c.Process.Image.Value)
	}
}

// The tuple is read off the field names rather than off the label a reader gave
// the record, so a reader that labels its evidence differently cannot break the
// join without also changing the field names, which are the rules' own.
func TestTheSideIsReadFromTheFieldsAndNotTheLabel(t *testing.T) {
	ix := New()
	mislabelled := zeekFlow()
	mislabelled.Origin.Product = ""
	mislabelled.Origin.Service = ""
	ix.Observe(hostConnection())

	if c := ix.Connection(mislabelled); c.Process.Image.Value == "" {
		t.Errorf("an unlabelled Zeek record lost its process: %q", c.Unresolved)
	}
}

// Case does not decide a match. A protocol written UDP and one written udp are
// the same protocol, and an address is an address.
func TestCaseDoesNotDecideAMatch(t *testing.T) {
	ix := New()
	shouty := hostConnection()
	shouty.Raw["Protocol"] = "TCP"
	ix.Observe(shouty)

	if c := ix.Connection(zeekFlow()); c.Process.Image.Value == "" {
		t.Errorf("TCP and tcp were treated as different protocols: %q", c.Unresolved)
	}
}

// Where a process went. This is the question a finding about a program leaves
// open — it opened lsass, and then what — and the answer is in records the
// finding itself never touches.
func TestAProcessGainsTheConnectionsItOpened(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	ix.Observe(hostConnection())

	// A second connection of the same process, with no flow on the wire.
	second := hostConnection()
	second.Raw["SourcePort"] = "51130"
	second.Raw["DestinationIp"], second.Raw["DestinationPort"] = "10.0.5.13", "8080"
	second.Origin.Record = 1400
	ix.Observe(second)

	// The acting process of a finding, which is a different record entirely:
	// a Sysmon 10 naming the same process by its identifier.
	finding := &event.Event{
		Class:   event.ClassProcess,
		Action:  "process opened another process",
		Process: event.Process{GUID: event.Seen("{81056205-5665-64dc-2704-000000000800}")},
		Raw:     event.Fields{"EventID": "10"},
	}

	r := ix.Network(finding)
	if r.Total != 2 {
		t.Fatalf("want both connections, got %d: %+v", r.Total, r)
	}
	if r.OnWire != 1 {
		t.Errorf("want one of them on the wire, got %d", r.OnWire)
	}

	var withFlow, without int
	for _, s := range r.Sightings {
		if s.Flow != nil {
			withFlow++
			if s.Flow.Received != "7373" {
				t.Errorf("the flow attached to the wrong connection: %+v", s.Flow)
			}
			if s.Remote != "10.0.5.13:80" {
				t.Errorf("remote end: %q", s.Remote)
			}
		} else {
			without++
			if s.Remote != "10.0.5.13:8080" {
				t.Errorf("remote end: %q", s.Remote)
			}
		}
	}
	if withFlow != 1 || without != 1 {
		t.Errorf("%d with a flow, %d without", withFlow, without)
	}
}

// A pid is reused, so a process is only asked about by the identifier that is
// unique over time. Answering by pid would hand a finding another process's
// connections, which is the same mistake as walking a lineage by pid.
func TestAProcessWithNoIdentifierIsNotAnswered(t *testing.T) {
	ix := New()
	ix.Observe(hostConnection())

	byPID := &event.Event{
		Process: event.Process{PID: event.Seen("7476")},
		Raw:     event.Fields{"EventID": "1"},
	}
	r := ix.Network(byPID)
	if r.Total != 0 {
		t.Fatalf("connections were attributed by pid: %+v", r)
	}
	// And it says why, because a blank reads as "this process opened nothing".
	if r.Unresolved == "" {
		t.Error("nothing was attributed and nothing says why")
	}
}

// A connection the host recorded without a process identifier is still useful
// for the five-tuple join and cannot be filed under a process.
func TestAConnectionWithNoProcessIdentifierIsStillJoinedByTuple(t *testing.T) {
	ix := New()
	noGUID := hostConnection()
	noGUID.Process.GUID = event.Field{}
	ix.Observe(noGUID)

	if c := ix.Connection(zeekFlow()); c.Process.Image.Value == "" {
		t.Errorf("the tuple join lost a record that has no process identifier: %q", c.Unresolved)
	}
}

// Which end is the far end comes out of the record. Sysmon writes whether the
// connection was initiated here, and on an inbound one the far end is the
// source — reading that is not a judgement, the provider wrote it down.
func TestTheFarEndOfAnInboundConnectionIsTheSource(t *testing.T) {
	ix := New()
	inbound := hostConnection()
	inbound.Raw["Initiated"] = "false"
	ix.Observe(inbound)

	finding := &event.Event{
		Process: event.Process{GUID: event.Seen("{81056205-5665-64dc-2704-000000000800}")},
		Raw:     event.Fields{"EventID": "10"},
	}
	r := ix.Network(finding)
	if len(r.Sightings) != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Sightings[0].Remote != "192.168.1.41:51126" {
		t.Errorf("an inbound connection reported %q as the far end", r.Sightings[0].Remote)
	}
}

// An ambiguous tuple attaches no flow here either. The count still says the
// connection happened, because the host recorded it; what is missing is what
// crossed, and inventing it from one of two candidates would be a guess.
func TestAnAmbiguousTupleAttachesNoFlowToAProcess(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	second := zeekFlow()
	second.Raw["uid"] = "Cother"
	second.Origin.Record = 44
	ix.Observe(second)
	ix.Observe(hostConnection())

	r := ix.Network(&event.Event{
		Process: event.Process{GUID: event.Seen("{81056205-5665-64dc-2704-000000000800}")},
		Raw:     event.Fields{"EventID": "10"},
	})
	if r.Total != 1 {
		t.Fatalf("%+v", r)
	}
	if r.OnWire != 0 || r.Sightings[0].Flow != nil {
		t.Error("one of two flows sharing a tuple was attached anyway")
	}
}

// Row 11 of LSASS_campaign_01/files.log, unchanged: the PE carried by the
// conn.log row in zeekFlow(). Endpoints and uid, no protocol.
func zeekFile() *event.Event {
	return &event.Event{
		Class:  event.ClassFile,
		Action: "file seen on the wire",
		Origin: event.Origin{Product: "zeek", Service: "files", Path: "files.log", Record: 11},
		Raw: event.Fields{
			"ts": "1692161648.333854", "fuid": "FmHWcO2PF9wbqM6cil", "uid": "CwSLisOv4lXMZlXd3",
			"id.orig_h": "192.168.1.41", "id.orig_p": "51126",
			"id.resp_h": "10.0.5.13", "id.resp_p": "80",
			"source": "HTTP", "depth": "0", "analyzers": "PE",
			"mime_type": "application/x-dosexec", "duration": "0.001217",
			"local_orig": "T", "is_orig": "F", "seen_bytes": "7168", "total_bytes": "7168",
			"missing_bytes": "0", "overflow_bytes": "0", "timedout": "F",
		},
	}
}

func TestAFileOnTheWireReachesItsProcessThroughTheZeekUID(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	ix.Observe(hostConnection())

	c := ix.Connection(zeekFile())
	if !c.Found() {
		t.Fatalf("the file was not attributed: %q", c.Unresolved)
	}
	if !strings.HasSuffix(c.Process.Image.Value, `\msedge.exe`) || c.Process.Image.Trusted() {
		t.Errorf("process: %+v", c.Process.Image)
	}
	if !strings.Contains(c.Why, "CwSLisOv4lXMZlXd3") {
		t.Errorf("the reason does not name the uid it joined through: %q", c.Why)
	}
}

func TestAFileWhoseConnectionIsMissingSaysSo(t *testing.T) {
	ix := New()
	ix.Observe(hostConnection()) // no conn.log row
	if c := ix.Connection(zeekFile()); c.Found() || c.Unresolved == "" {
		t.Fatalf("got %+v; a blank reads as \"nobody asked for it\"", c)
	}
}

func TestAUIDNamingTwoConnectionsIsReportedRatherThanGuessed(t *testing.T) {
	ix := New()
	ix.Observe(hostConnection())
	ix.Observe(zeekFlow())
	other := zeekFlow()
	other.Raw["id.orig_p"] = "51127"
	ix.Observe(other)

	if c := ix.Connection(zeekFile()); c.Found() || !strings.Contains(c.Unresolved, "more than one") {
		t.Fatalf("got %+v", c)
	}
}

func TestARecordFromTheWireIsNotAskedWhereItsProcessWent(t *testing.T) {
	ix := New()
	ix.Observe(zeekFlow())
	ix.Observe(hostConnection())
	if r := ix.Network(zeekFile()); r.Unresolved != "" || r.Total != 0 {
		t.Errorf("a files.log record was answered as if it named a process: %+v", r)
	}
}

// The pe.log row of LSASS_campaign_01, unchanged. It names the file by Zeek's
// file id and nothing else.
func zeekPE() *event.Event {
	return &event.Event{
		Class:  event.ClassFile,
		Action: "executable analysed on the wire",
		Origin: event.Origin{Product: "zeek", Service: "pe", Path: "pe.log", Record: 9},
		Raw: event.Fields{
			"ts": "1692161648.333856", "id": "FmHWcO2PF9wbqM6cil", "machine": "AMD64",
			"compile_ts": "1271282813.000000", "os": "Windows 95 or NT 4.0", "subsystem": "WINDOWS_GUI",
			"is_exe": "T", "is_64bit": "T", "uses_aslr": "F", "uses_dep": "F", "uses_code_integrity": "F",
			"uses_seh": "T", "has_import_table": "T", "has_export_table": "F", "has_cert_table": "F",
			"has_debug_data": "F", "section_names": ".text,.rdata,.cmcq",
		},
	}
}

func TestAFileOnTheWireGainsWhatThePEAnalyserRead(t *testing.T) {
	ix := New()
	ix.Observe(zeekPE())
	a := ix.Executable(zeekFile())
	if a.Exe == nil {
		t.Fatalf("no PE record: %q", a.Unresolved)
	}
	if a.Exe.Machine != "AMD64" || a.Exe.Is64 != "T" || !strings.Contains(a.Why, "FmHWcO2PF9wbqM6cil") {
		t.Errorf("got %+v, why %q", a.Exe, a.Why)
	}
}

func TestAnAnalysedFileWithNoPERecordSaysSo(t *testing.T) {
	if a := New().Executable(zeekFile()); a.Exe != nil || !strings.Contains(a.Unresolved, "holds no record") {
		t.Fatalf("got %+v; a blank reads as \"not an executable\"", a)
	}
}

func TestAFileTheAnalyserNeverSawIsNotAskedAbout(t *testing.T) {
	f := zeekFile()
	f.Raw["analyzers"] = ""
	f.Raw["mime_type"] = "text/html"
	if a := New().Executable(f); a.Exe != nil || a.Unresolved != "" {
		t.Errorf("a file with no PE analysis was answered: %+v", a)
	}
}

func TestTwoPERowsWithOneFileIdAreReportedRatherThanGuessed(t *testing.T) {
	ix := New()
	ix.Observe(zeekPE())
	ix.Observe(zeekPE())
	if a := ix.Executable(zeekFile()); a.Exe != nil || !strings.Contains(a.Unresolved, "share") {
		t.Errorf("got %+v", a)
	}
}
