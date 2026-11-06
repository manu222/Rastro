package normalise

import "fmt"

// The provider tables.
//
// Every entry here was taken from the pinned corpus by counting how each field
// actually arrives: 31,243 records across 132 files, of which 56 distinct
// fields come back as something other than text. The two exceptions are marked,
// and they matter, because a declaration that the corpus cannot confirm is a
// declaration resting on somebody's memory.
//
// The right source for these is the provider's own manifest, which states the
// type of every field. For Security and Eventlog it has now been read
// (manifest.go, from scripts/manifest-forms.ps1) and every entry below agrees
// with it; a test fails the build the day one does not. Sysmon's was read from
// v15.22 afterwards, and its fourteen entries agree as well.
//
// The audit has already earned its place. Its first run found twelve fields
// arriving as integers that no table described, every one of them written in
// hexadecimal by Windows itself, and a rule matching 0x3e7 against the number
// 999 fails exactly the way the GrantedAccess bug did: silently. Each of the
// entries added for it carries the record it was read off, because the XML of
// a real event is the only thing that settles what a provider writes.

// Sysmon writes its numeric fields in base ten, with one well-known exception.
var Sysmon = &Table{
	Producer: "Microsoft-Windows-Sysmon",
	Fields: map[string]Form{
		// Observed as integers in the corpus.
		"ProcessId":         FormDecimal,
		"ParentProcessId":   FormDecimal,
		"SourceProcessId":   FormDecimal,
		"TargetProcessId":   FormDecimal,
		"SourceThreadId":    FormDecimal,
		"NewThreadId":       FormDecimal,
		"TerminalSessionId": FormDecimal,
		"SourcePort":        FormDecimal,
		"DestinationPort":   FormDecimal,

		// Observed as booleans in the corpus.
		"Initiated":         FormBool,
		"SourceIsIpv6":      FormBool,
		"DestinationIsIpv6": FormBool,

		// Not confirmed by the corpus, whose parser returns GrantedAccess as
		// the text "0x1f1fff" every time; the Go parser this project uses
		// hands back a number instead, and a rule matching "0x1010" against
		// 4112 fails silently. It was declared from the provider's behaviour
		// and flagged as the first entry to re-check against the manifest.
		// Checked: Sysmon v15.22 declares it win:HexInt32.
		"GrantedAccess": FormHex,

		// And one that is hexadecimal while its neighbours are not. A Sysmon
		// process creation in this corpus writes ProcessId as 6636 and
		// LogonId as 0x391e334, in the same record, and both spellings are in
		// the raw XML of that record. Any shortcut of the form "identifiers
		// are hexadecimal" would have broken the first four entries of this
		// table; this is why the tables are per field and not per idea.
		"LogonId": FormHex,

		// From the manifest alone: no event of the corpus carries them.
		// IsExecutable is xs:boolean on the file block and detection events,
		// Session is xs:unsignedInt.
		"IsExecutable": FormBool,
		"Session":      FormDecimal,
	},
}

// SecurityAuditing is the built-in Windows audit provider. Its own convention
// differs from Sysmon's: several identifiers are written in hexadecimal, which
// is why a single table shared by all providers would have to be wrong for one
// of them.
var SecurityAuditing = &Table{
	Producer: "Microsoft-Windows-Security-Auditing",
	Fields: map[string]Form{
		"LogonType":          FormDecimal,
		"KeyLength":          FormDecimal,
		"EventIdx":           FormDecimal,
		"EventCountTotal":    FormDecimal,
		"FilterRTID":         FormDecimal,
		"LayerRTID":          FormDecimal,
		"NewState":           FormDecimal,
		"RestrictedSidCount": FormDecimal,
		"ProcessID":          FormDecimal,
		"Protocol":           FormDecimal,

		// Written as a message table reference, %%1833 and friends. The parser
		// sometimes hands back the bare number instead, and turning that into
		// an integer would silently convert a label into a quantity.
		"ImpersonationLevel": FormMessageRef,

		// Hexadecimal, every one of them, and every one read off the raw XML
		// of a record of this corpus rather than assumed:
		//
		//	4688  ProcessId 0x274         NewProcessId 0x24e0
		//	4688  SubjectLogonId 0x3e7
		//	4624  SubjectLogonId 0x79e59  TargetLogonId 0x1cd964
		//	4624  TargetLinkedLogonId 0x1cd8f6
		//	4625  Status 0xC000006D       SubStatus 0xC000006A
		//	4656  AccessMask 0x1f3fff     HandleId 0x558
		//	4663  AccessMask 0x1          HandleId 0x50
		//	4768  TicketOptions 0x10      TicketEncryptionType 0x12
		//
		// Note ProcessId here against ProcessId in the Sysmon table above: the
		// same field name, written in base sixteen by one provider and base
		// ten by the other. A shared table would have to be wrong for one of
		// them, and the one it was wrong for would fail without saying so.
		//
		// What this costs if it is wrong is worth stating: these values are
		// what the rules see, so a field declared hexadecimal that the
		// provider writes in decimal stops every rule matching it. That is why
		// each line has a record behind it.
		"ProcessId":            FormHex,
		"NewProcessId":         FormHex,
		"SubjectLogonId":       FormHex,
		"TargetLogonId":        FormHex,
		"TargetLinkedLogonId":  FormHex,
		"Status":               FormHex,
		"SubStatus":            FormHex,
		"AccessMask":           FormHex,
		"HandleId":             FormHex,
		"TicketOptions":        FormHex,
		"TicketEncryptionType": FormHex,
	},
	Events: map[int]map[string]Form{
		// The Filtering Platform writes the process id in base ten where the
		// rest of this provider writes it in base sixteen. Read off the
		// compound corpus, where campaign 01 alone has 195 records of 5158
		// with ProcessId 1048 beside 4656, 4673 and 4688 in the same file
		// with 0x11c0 and 0x1d18. Declared provider-wide, it made the shipper
		// audit blame the shipper for all 954 of them across campaigns 01-04,
		// and on the EVTX path it would turn an integer 1048 into 0x418.
		//
		// 5152 is the same platform dropping a packet. Sixteen of its records
		// in campaign 01 carry ProcessId 0, the same text in either base, and
		// confirm nothing; the one that settles it is in campaign 02, ProcessId
		// 4, the System process, written as Windows writes it. 5156 calls the
		// same field ProcessID and is already declared decimal above.
		5152: {"ProcessId": FormDecimal},
		5158: {"ProcessId": FormDecimal},
	},
}

// Eventlog is the provider behind the two events that report the log was
// cleared, 1102 on the Security channel and 104 on System. It writes one
// numeric field and writes it the way the Security provider does: the session
// that cleared the log on DC1 appears as 0x8d7099 in a 5136 of the same host
// and the same session, and the 1102 carries the same identifier.
//
// A table with one field in it is still worth declaring, because declaring it
// is what puts the provider under the audit: from here on, a second numeric
// field appearing on an Eventlog record fails the build instead of passing
// unnoticed.
var Eventlog = &Table{
	Producer: "Microsoft-Windows-Eventlog",
	Fields: map[string]Form{
		"SubjectLogonId": FormHex,
	},
}

// manifest is a provider's own declaration of its fields, generated in
// manifest.go.
type manifest struct {
	Fields map[string]Form
	Events map[int]map[string]Form
}

// conflicts lists every place a hand table contradicts its provider's
// manifest. Empty is the only acceptable value; a test holds it there.
var conflicts []string

func init() {
	merge(SecurityAuditing, securityManifest)
	merge(Eventlog, eventlogManifest)
	merge(Sysmon, sysmonManifest)
}

// merge adds what the manifest declares and the hand table does not. Where
// both speak and disagree, the hand table is kept and the disagreement is
// recorded, so that the build fails rather than one of them winning quietly.
func merge(t *Table, m manifest) {
	for field, f := range m.Fields {
		if have, ok := t.Fields[field]; ok {
			if have != f && !(have == FormMessageRef && f == FormText) {
				conflicts = append(conflicts, fmt.Sprintf("%s %s: table %s, manifest %s", t.Producer, field, have, f))
			}
			continue
		}
		t.Fields[field] = f
	}
	if len(m.Events) > 0 && t.Events == nil {
		t.Events = map[int]map[string]Form{}
	}
	for id, fields := range m.Events {
		for field, f := range fields {
			if have, ok := t.Events[id][field]; ok {
				if have != f {
					conflicts = append(conflicts, fmt.Sprintf("%s %d %s: table %s, manifest %s", t.Producer, id, field, have, f))
				}
				continue
			}
			if t.Events[id] == nil {
				t.Events[id] = map[string]Form{}
			}
			t.Events[id][field] = f
		}
	}
}

// Default is the set of tables the EVTX reader starts from.
func Default() *Normaliser { return New(Sysmon, SecurityAuditing, Eventlog) }
