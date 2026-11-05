package winevent

import "strings"

// A Sigma rule can say what kind of record it is written for without naming the
// provider or the event id. `category: process_access` means "a process opened
// a handle to another one", and it is the rule author's way of writing one rule
// that works whether the evidence came from Sysmon or from somewhere else.
//
// Nothing in the evidence says which category a record belongs to. The category
// is a name Sigma gives to a set of (provider, event id) pairs, so a reader that
// does not translate the pair into the name filters out every rule that uses
// one — and does it before the rule is ever evaluated, which makes it silent.
// That is what happened here: eight of the thirteen rules in this repository
// and 2,286 of SigmaHQ's declare a category, and until this file existed not
// one of them could be offered a single record.
//
// The table is not from memory. It is pySigma's own
// specific_to_generic_logsource_mapping, read out of version 2.0.2, plus the
// two PowerShell categories from SigmaHQ's logsource guides. An event id that
// neither source names is left out: inventing a category would put a rule in
// front of evidence its author never meant it to see, which is the same kind of
// false positive as letting a Zeek rule match a Windows record.
//
// Several categories can be right at once, and that is not sloppiness in the
// taxonomy. A Sysmon 13 is a registry_set to a rule that cares what was
// written and a registry_event to one that only cares that the registry was
// touched; both rules are correct and both have to see the record.

// categories is keyed by provider and event id. The Sysmon registry events get
// their second answer from the record itself, in Categories below, because
// whether a 12 created or deleted a key is written in the record and not in the
// event id.
var categories = map[string]map[int][]string{
	sysmon: {
		1:  {"process_creation"},
		2:  {"file_change"},
		3:  {"network_connection"},
		4:  {"sysmon_status"},
		5:  {"process_termination"},
		6:  {"driver_load"},
		7:  {"image_load"},
		8:  {"create_remote_thread"},
		9:  {"raw_access_thread"},
		10: {"process_access"},
		11: {"file_event"},
		12: {"registry_event"},
		13: {"registry_set", "registry_event"},
		14: {"registry_rename", "registry_event"},
		15: {"create_stream_hash"},
		16: {"sysmon_status"},
		17: {"pipe_created"},
		18: {"pipe_created"},
		19: {"wmi_event"},
		20: {"wmi_event"},
		21: {"wmi_event"},
		22: {"dns_query"},
		23: {"file_delete"},
		24: {"clipboard_change"},
		25: {"process_tampering"},
		26: {"file_delete_detected"},
		27: {"file_block_executable"},
		28: {"file_block_shredding"},
		29: {"file_executable_detected"},
		// Sysmon's own error channel. Worth categorising because a rule that
		// watches for the sensor failing is watching for an attacker blinding
		// it.
		255: {"sysmon_error"},
	},
	security: {
		// The only Security event pySigma maps to a generic category. The rest
		// of the Security rules in the public corpus name the service instead,
		// which the reader already answers.
		4688: {"process_creation"},
	},
	powersh: {
		// From SigmaHQ's logsource guides: ps_module is the pipeline execution
		// detail and ps_script is the script block, and the two are different
		// events of the same provider.
		4103: {"ps_module"},
		4104: {"ps_script"},
	},
}

// Categories reports every Sigma category one record answers to, or nothing
// when neither source names its event id.
//
// The registry events are the reason this takes the record and not just the id.
// Sysmon writes CreateKey and DeleteKey as two values of one event, 12, and
// Sigma splits them into registry_add and registry_delete. The id alone cannot
// tell them apart, and answering both would let a rule written for a deletion
// fire on a key being created.
func Categories(f Flat) []string {
	byID, ok := categories[f.Producer]
	if !ok {
		return nil
	}
	base := byID[f.EventID]
	if f.Producer != sysmon || f.EventID != 12 {
		return base
	}

	switch strings.TrimSpace(f.Fields["EventType"]) {
	case "CreateKey":
		return []string{"registry_add", "registry_event"}
	case "DeleteKey":
		return []string{"registry_delete", "registry_event"}
	}
	// A 12 that does not say which it was is still a registry event, and
	// nothing more specific can honestly be claimed about it.
	return base
}
