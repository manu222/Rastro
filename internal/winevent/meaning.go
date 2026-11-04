package winevent

import "strconv"

// Windows writes some of its most important values as numbers and as
// references into a message table. A report that shows them raw asks the
// analyst to look them up:
//
//	LogonType          5
//	ImpersonationLevel %%1833
//	Status             3221225581
//
// This file translates the ones whose meaning can be shown rather than
// remembered, and leaves every other one exactly as the provider wrote it. An
// untranslated code in a report is a gap the reader can see and look up; a
// wrong label is a lie the reader has no way to catch, and the whole point of
// this project is the difference between those two things.
//
// The raw field is never touched. Detection matches %%1833, because that is
// what the rules are written against and what the evidence says; the
// translation exists for the lines a person reads.

// LogonTypeName returns what a logon type number means.
//
// These are not message-table references and never were. They are a documented
// enumeration, stable since Windows 2000, published by Microsoft in the
// description of event 4624 — and 0 does not appear in it, so a 0 is left as a
// number rather than called "System".
func LogonTypeName(v string) (string, bool) {
	switch v {
	case "2":
		return "interactive", true
	case "3":
		return "network", true
	case "4":
		return "batch", true
	case "5":
		return "service", true
	case "7":
		return "unlock", true
	case "8":
		return "network cleartext", true
	case "9":
		return "new credentials", true
	case "10":
		return "remote interactive", true
	case "11":
		return "cached interactive", true
	}
	return v, false
}

// messageRefs is the translation table for the %%NNNN references.
//
// Every entry was resolved by making a real Windows installation render a
// record out of this corpus and reading what it called the value — not from
// memory, and not from a documentation page about a different version. Where
// the rendered record is demonstrably the same record the raw dump shows, that
// is noted; where it is a different record of the same event, the entry is only
// here because the field carries exactly one code in the whole corpus, so there
// is nothing for the label to be attached to but that code.
//
// The machine that rendered them runs Windows in Spanish, so the labels below
// are the English of what it said: "<valor no establecido>" is "value not set".
// The translation of the label is mine; the meaning is the machine's.
//
// Codes NOT in here are left as written, and `rastro read -codes` lists them.
// The ones outstanding are the two spellings of ImpersonationLevel, the two of
// TokenElevationType, the pair on AuditPolicyChanges, the two on OperationType,
// and fourteen audit category identifiers that appear once each. Nothing is
// guessed to fill the gap: an untranslated code is a gap the reader can look
// up, and a wrong label is one they cannot catch.
var messageRefs = map[string]string{
	// The yes/no pair, confirmed on a 4826 whose boot configuration had kernel
	// debugging on and four other options off: KernelDebug was %%1842 and came
	// out as "Sí", while AdvancedOptions, RemoteEventLogging, HypervisorDebug
	// and DisableIntegrityChecks were all %%1843 and all came out as "No".
	"%%1842": "yes",
	"%%1843": "no",

	// AccountExpires and PasswordLastSet on the 4720 that created an account in
	// this corpus. Both carried %%1794 and both rendered as "<nunca>".
	"%%1794": "never",
	// UserParameters on the same record: Windows says there is a value and
	// declines to print it. Worth keeping precisely because it is not nothing.
	"%%1792": "changed, not shown",

	// ConfigAccessPolicy and the two launch-type fields of a 4826. Each of
	// those fields carries one code and only one across the whole corpus, and
	// the rendered record calls them "Predeterminado" and "Desactivado".
	"%%1846": "default",
	"%%1848": "off",

	// The 5156 of this corpus is a single record, and it is the one that was
	// rendered: Direction %%14593 came out as outbound and LayerName %%14611 as
	// the connect layer of the filtering platform.
	"%%14593": "outbound",
	"%%14611": "connect",

	// DSType on a 5136. Forty sightings, one code, and the rendered record
	// calls it "Servicios de dominio de Active Directory".
	"%%14676": "Active Directory Domain Services",

	// FailureReason on the only 4625 in the corpus, and the rendered record is
	// that record: same status 0xC000006D, same substatus 0xC000006A, same
	// calling process. This is the label that tells a wrong password apart from
	// a name that does not exist, which is the distinction a triage report
	// exists to make.
	"%%2313": "unknown user name or bad password",

	// ImpersonationLevel, resolved off the two records that carry each code.
	// Record 137225 of a Security log, a local Chrome logon, has %%1833 and
	// renders as "Suplantación"; record 2988522, a Kerberos network logon from
	// a machine account, has %%1840 and renders as "Delegación". That second
	// record is also where the yes/no pair was nailed down a second time: it
	// carries ElevatedToken %%1842 and VirtualAccount %%1843 and renders them
	// "Sí" and "No" in the same message.
	"%%1833": "impersonation",
	"%%1840": "delegation",

	// AuditPolicyChanges on two 4719 records of the same domain controller.
	// Record 198238538 has %%8449 and says "Resultado positivo agregado";
	// record 198239064 has %%8451 and says "Error agregado". Which half of the
	// policy was switched on matters: an attacker who turns success auditing
	// off is hiding what worked.
	"%%8449": "success added",
	"%%8451": "failure added",

	// OperationType on two 5136 records written a tick apart, both by the
	// account "bob" against the same group policy container. Record 198239047
	// has %%14674 and says "Valor agregado"; 198239046 has %%14675 and says
	// "Valor eliminado". A modification to a GPO reads very differently
	// depending on which of the two it was.
	"%%14674": "value added",
	"%%14675": "value deleted",

	// Two of the fourteen audit category identifiers, paired exactly because
	// they came off the same two 4719 records as the codes above. The other
	// twelve appear once each and are still outstanding.
	"%%8278":  "account management",
	"%%8279":  "DS access",
	"%%13825": "computer account management",
	"%%14081": "directory service changes",
}

// TokenElevationType is deliberately absent, and for a reason worth recording:
// Windows itself did not resolve it. Both 4688 records rendered on a real
// installation printed "Tipo de elevación de token: %%1936" and "%%1937"
// verbatim, because the parameter strings for that field were not available on
// that machine. The message's own explanatory text describes types 1, 2 and 3 —
// full, elevated and limited — and %%1936 is almost certainly type 1, but
// "almost certainly" derived from arithmetic on a message number is exactly the
// kind of reasoning this table exists to keep out. It stays a code.

// Explain translates a value a person is about to read, and reports whether
// anything was translated. The field name decides: a number means one thing
// under LogonType and something else everywhere else.
func Explain(field, value string) (string, bool) {
	if value == "" {
		return value, false
	}
	if label, ok := messageRefs[value]; ok {
		return label, true
	}
	switch field {
	case "LogonType":
		return LogonTypeName(value)
	case "Status", "SubStatus":
		if label, ok := statusName(value); ok {
			return label, true
		}
	}
	return value, false
}

// statusName translates the logon failure codes of a 4625.
//
// Windows writes them in decimal, so 3221225581 has to be read as 0xC000006D
// before it means anything. These four are the ones that distinguish a user
// typing a wrong password from an attacker spraying names at a domain
// controller, which is a distinction a triage report exists to make. Their
// values are NTSTATUS constants, not a Windows version's idea of them.
func statusName(v string) (string, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return v, false
	}
	switch n {
	case 0xC000006D:
		return "logon failure", true
	case 0xC000006A:
		return "wrong password", true
	case 0xC0000064:
		return "no such user", true
	case 0xC0000234:
		return "account locked out", true
	case 0xC0000072:
		return "account disabled", true
	}
	return v, false
}

// IsMessageRef reports whether a value is a reference into a provider's message
// table rather than a value in its own right. The audit uses it to count which
// codes the evidence contains.
func IsMessageRef(v string) bool {
	if len(v) < 3 || v[0] != '%' || v[1] != '%' {
		return false
	}
	for _, c := range v[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
