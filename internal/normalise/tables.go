package normalise

// The provider tables.
//
// Every entry here was taken from the pinned corpus by counting how each field
// actually arrives: 31,243 records across 132 files, of which 56 distinct
// fields come back as something other than text. The two exceptions are marked,
// and they matter, because a declaration that the corpus cannot confirm is a
// declaration resting on somebody's memory.
//
// The right source for these is the provider's own manifest, which states the
// type of every field (wevtutil gp <provider> /ge /gm). Until that is extracted
// on a machine with the providers installed, this is the best available
// approximation and the audit is what keeps it honest.

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

		// NOT confirmed by the corpus. The parser used to survey it returns
		// GrantedAccess as the text "0x1f1fff" every time, so the corpus has
		// nothing to say about what happens when a parser hands back a number
		// instead. The Go parser this project uses does exactly that — it is
		// the finding the feasibility probe recorded — and a rule matching
		// "0x1010" against the number 4112 fails silently. Declared from the
		// provider's behaviour rather than from the evidence, and the first
		// entry to re-check against the manifest.
		"GrantedAccess": FormHex,
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
	},
}

// Default is the set of tables the EVTX reader starts from.
func Default() *Normaliser { return New(Sysmon, SecurityAuditing) }
