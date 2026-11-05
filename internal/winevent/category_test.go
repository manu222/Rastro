package winevent

import (
	"strings"
	"testing"
)

// The pairs, pinned. Every one of these was read out of pySigma's
// specific_to_generic_logsource_mapping or SigmaHQ's own logsource guides, and
// a change to any of them silently stops a set of rules from ever seeing their
// evidence — which is exactly what the absence of this table did.
func TestTheCategoriesSigmaGivesToEachEvent(t *testing.T) {
	for _, c := range []struct {
		producer string
		id       int
		want     string
	}{
		{sysmon, 1, "process_creation"},
		{sysmon, 3, "network_connection"},
		{sysmon, 7, "image_load"},
		{sysmon, 8, "create_remote_thread"},
		{sysmon, 10, "process_access"},
		{sysmon, 11, "file_event"},
		{sysmon, 13, "registry_set,registry_event"},
		{sysmon, 14, "registry_rename,registry_event"},
		{sysmon, 15, "create_stream_hash"},
		{sysmon, 17, "pipe_created"},
		{sysmon, 18, "pipe_created"},
		{sysmon, 22, "dns_query"},
		{sysmon, 23, "file_delete"},
		{security, 4688, "process_creation"},
		{powersh, 4103, "ps_module"},
		{powersh, 4104, "ps_script"},
	} {
		f := Flat{Producer: c.producer, EventID: c.id, Fields: map[string]string{}}
		got := strings.Join(Categories(f), ",")
		if got != c.want {
			t.Errorf("%s event %d: want %q, got %q", c.producer, c.id, c.want, got)
		}
	}
}

// A Sysmon 12 is a key created or a key deleted, and Sigma has a different name
// for each. The id does not say which; the record does. Answering both would
// put a rule written for a deletion in front of a key being created.
func TestASysmonRegistryKeyEventIsReadFromTheRecord(t *testing.T) {
	for eventType, want := range map[string]string{
		"CreateKey": "registry_add,registry_event",
		"DeleteKey": "registry_delete,registry_event",
		// Nothing said. Still a registry event, and nothing more specific can
		// honestly be claimed.
		"":         "registry_event",
		"Nonsense": "registry_event",
	} {
		f := Flat{Producer: sysmon, EventID: 12, Fields: map[string]string{"EventType": eventType}}
		got := strings.Join(Categories(f), ",")
		if got != want {
			t.Errorf("EventType %q: want %q, got %q", eventType, want, got)
		}
	}
}

// An event id neither source names gets nothing. Inventing a category would put
// a rule in front of evidence its author never saw, which is a false positive
// with a rule's name on it rather than a near miss.
func TestAnEventNobodyHasNamedGetsNoCategory(t *testing.T) {
	for _, c := range []struct {
		producer string
		id       int
	}{
		{sysmon, 99},
		{security, 4624}, // a logon: the rules for it name the service, not a category
		{security, 1102},
		{eventlog, 104},
		{scm, 7036},
		{"Some-Provider-Nobody-Described", 1},
	} {
		f := Flat{Producer: c.producer, EventID: c.id, Fields: map[string]string{}}
		if got := Categories(f); len(got) != 0 {
			t.Errorf("%s event %d was given %v", c.producer, c.id, got)
		}
	}
}

// The table has to answer for the whole range Sysmon writes, because a gap in it
// is a set of rules that loads and never fires. Every id from 1 to 29 is a real
// Sysmon event, and the ones with no entry are the ones pySigma does not map.
func TestEverySysmonEventTheTableCoversHasANonEmptyName(t *testing.T) {
	missing := []int{}
	for id := 1; id <= 29; id++ {
		f := Flat{Producer: sysmon, EventID: id, Fields: map[string]string{}}
		cats := Categories(f)
		if len(cats) == 0 {
			missing = append(missing, id)
			continue
		}
		for _, c := range cats {
			if strings.TrimSpace(c) == "" {
				t.Errorf("Sysmon %d produced an empty category name", id)
			}
		}
	}
	if len(missing) != 0 {
		t.Errorf("Sysmon event(s) %v have no category; pySigma maps every id from 1 to 29", missing)
	}
}
