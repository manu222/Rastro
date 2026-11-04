package event

import (
	"strconv"
	"testing"
	"time"
)

// These measure one question: what does it cost to produce an Event, and is
// that cost worth avoiding by reusing a single struct across a whole file?
//
// The field list is a real Sysmon process creation record — twenty-two fields,
// counted from the samples in datasets/ — because the answer depends almost
// entirely on the map that carries them.

var sysmonProcessCreation = [][2]string{
	{"CommandLine", `"C:\Windows\System32\rundll32.exe" zipfldr.dll,RouteTheCall c:\Windows\System32\calc.exe`},
	{"Company", "Microsoft Corporation"},
	{"CurrentDirectory", `C:\`},
	{"Description", "Windows host process (Rundll32)"},
	{"FileVersion", "10.0.17763.1 (WinBuild.160101.0800)"},
	{"Hashes", "SHA1=0873F40DE395DE017495ED5C7E693AFB55E9F867,MD5=A3F446F1E2B8C6ECE56F608FB32B8DC6"},
	{"Image", `C:\Windows\System32\rundll32.exe`},
	{"IntegrityLevel", "High"},
	{"LogonGuid", "DFAE8213-7002-5CDD-0000-0020E6850500"},
	{"LogonId", "0x585e6"},
	{"OriginalFileName", "RUNDLL32.EXE"},
	{"ParentCommandLine", `"C:\Windows\system32\cmd.exe"`},
	{"ParentImage", `C:\Windows\System32\cmd.exe`},
	{"ParentProcessGuid", "DFAE8213-702C-5CDD-0000-0010E8C50600"},
	{"ParentProcessId", "3748"},
	{"ProcessGuid", "DFAE8213-70EB-5CDD-0000-0010F66D0A00"},
	{"ProcessId", "3788"},
	{"Product", "Microsoft Windows Operating System"},
	{"RuleName", "-"},
	{"TerminalSessionId", "2"},
	{"User", `insecurebank\Administrator`},
	{"UtcTime", "2019-05-16 14:17:15.753"},
}

// fill populates an event the way a source mapper would.
func fill(e *Event, i int) {
	e.Time = time.Unix(int64(1557000000+i), 0).UTC()
	e.Class = ClassProcess
	e.Activity = "ProcessCreate"
	e.Origin = Origin{Path: "Execution/sample.evtx", Record: int64(i), Producer: "Microsoft-Windows-Sysmon/Operational"}
	e.Host = Seen("MSEDGEWIN10")
	e.User = Seen(`insecurebank\Administrator`)
	e.Process = Process{
		Image:       Seen(`C:\Windows\System32\rundll32.exe`),
		CommandLine: Seen(sysmonProcessCreation[0][1]),
		PID:         Seen(strconv.Itoa(3788 + i)),
		GUID:        Seen("DFAE8213-70EB-5CDD-0000-0010F66D0A00"),
	}
	e.Parent = Process{
		Image: Seen(`C:\Windows\System32\cmd.exe`),
		PID:   Seen("3748"),
	}
	e.Add(KindHost, "", e.Host)
	e.Add(KindAccount, "actor", e.User)
	e.Add(KindFile, "image", e.Process.Image)
	for _, kv := range sysmonProcessCreation {
		e.Raw[kv[0]] = kv[1]
	}
}

// BenchmarkAllocatePerEvent builds a fresh Event per record, which is what a
// consumer can safely keep a pointer to.
func BenchmarkAllocatePerEvent(b *testing.B) {
	b.ReportAllocs()
	var sink *Event
	for i := 0; i < b.N; i++ {
		e := &Event{Raw: make(Fields, len(sysmonProcessCreation))}
		fill(e, i)
		sink = e
	}
	_ = sink
}

// BenchmarkReuseOneEvent fills the same struct over and over, which is what a
// reader would do to avoid the allocation — at the cost that nobody downstream
// may keep the pointer.
func BenchmarkReuseOneEvent(b *testing.B) {
	b.ReportAllocs()
	e := &Event{Raw: make(Fields, len(sysmonProcessCreation))}
	for i := 0; i < b.N; i++ {
		e.Entities = e.Entities[:0]
		for k := range e.Raw {
			delete(e.Raw, k)
		}
		fill(e, i)
	}
	_ = e
}
