package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The evidence of the collection tests: three Security records as a shipper
// writes them. The machine names itself in two cases, and the second record is
// event 1101, the audit subsystem saying it dropped events.
const collectedEvents = `{"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","Hostname":"WS01","TimeCreated":"2026-11-10T11:30:00.000Z","EventID":4624,"TargetUserName":"ana","TargetDomainName":"LAB","TargetLogonId":"0x51","LogonType":"2"}
{"SourceName":"Microsoft-Windows-Eventlog","Channel":"Security","Hostname":"WS01","TimeCreated":"2026-11-10T11:32:02.000Z","EventID":1101,"Reason":"0"}
{"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","Hostname":"ws01","TimeCreated":"2026-11-10T11:33:00.000Z","EventID":4634,"TargetUserName":"ana","TargetDomainName":"LAB","TargetLogonId":"0x51","LogonType":"2"}
`

func collectionZip(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "Collection-WS01-2026-11-10.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string]string{
		"collection_context.json":              `{"session_id":"F.TEST","total_uploaded_files":1}`,
		"client_info.json":                     `{"Hostname":"WS01"}`,
		"log.json":                             `{"level":"DEFAULT","message":"done"}` + "\n",
		"requests.json":                        `{"items":[]}`,
		"uploads.json":                         `{"vfs_path":"C:\\logs\\security.json","_Components":["uploads","auto","C:","logs","security.json"],"file_size":` + strconv.Itoa(len(collectedEvents)) + `,"uploaded_size":` + strconv.Itoa(len(collectedEvents)) + `}` + "\n",
		"uploads/auto/C%3A/logs/security.json": collectedEvents,
	} {
		e, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		e.Write([]byte(body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path
}

// A collection handed over as its zip is read without unpacking it by hand:
// the copied file is the only evidence, the JSON describing the copy is not
// counted as unreadable records, the origin names the archive, the report says
// what the collection's own account of itself checks out to, and nothing is
// left in the temporary directory.
func TestACollectionIsReadFromItsZip(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("TMP", os.Getenv("TMPDIR"))
	t.Setenv("TEMP", os.Getenv("TMPDIR"))
	archive := collectionZip(t, t.TempDir())

	in, _, _, err := analyse(filepath.Join(root, "rules"), archive)
	if err != nil {
		t.Fatal(err)
	}
	if in.Files != 1 || in.Records != 3 || in.UnreadableRecords != 0 {
		t.Errorf("files %d, records %d, unreadable %d; want 1, 3, 0", in.Files, in.Records, in.UnreadableRecords)
	}
	if len(in.Hosts) != 1 || in.Hosts[0] != "WS01" {
		t.Errorf("machines %v; want the one machine, in the spelling most records use", in.Hosts)
	}
	notes := strings.Join(in.Notes, "\n")
	for _, want := range []string{
		"Velociraptor collection Collection-WS01-2026-11-10.zip of WS01 (F.TEST): 1 file(s) listed as copied, 1 present",
		"records no hash",
		"The Security log of WS01 says 1 time(s) that audit events were dropped",
		"Collection-WS01-2026-11-10.zip/uploads/auto/C%3A/logs/security.json record 2",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q:\n%s", want, notes)
		}
	}
	if left, _ := os.ReadDir(os.Getenv("TMPDIR")); len(left) != 0 {
		t.Errorf("%d entries left in the temporary directory", len(left))
	}
}

// A zip lying inside an evidence folder is not opened, and the report says so
// by name instead of walking past it.
func TestAnArchiveLeftInTheEvidenceIsNamed(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	dir := t.TempDir()
	collectionZip(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(collectedEvents), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _, _, err := analyse(filepath.Join(root, "rules"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if in.Records != 3 {
		t.Errorf("%d records", in.Records)
	}
	if notes := strings.Join(in.Notes, "\n"); !strings.Contains(notes, "1 archive(s) in the evidence were not opened") ||
		!strings.Contains(notes, "Collection-WS01-2026-11-10.zip") {
		t.Errorf("the unopened archive is not named:\n%s", notes)
	}
}

// A zip that is not a collection is an error, not an analysis of nothing.
func TestAZipThatIsNotACollectionIsRefused(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	path := filepath.Join(t.TempDir(), "photos.zip")
	f, _ := os.Create(path)
	w := zip.NewWriter(f)
	e, _ := w.Create("a.txt")
	e.Write([]byte("x"))
	w.Close()
	f.Close()
	if _, _, _, err := analyse(filepath.Join(root, "rules"), path); err == nil || !strings.Contains(err.Error(), "not a Velociraptor collection") {
		t.Errorf("error %v", err)
	}
}
