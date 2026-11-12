package velociraptor

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// build writes a collection shaped like the one Velociraptor 0.77.3's offline
// collector left for a Windows machine: two copied logs, one of them with the
// %4 a channel name carries, which the collector writes as %254.
func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(body string) string {
		h := sha256.Sum256([]byte(body))
		return hex.EncodeToString(h[:])
	}
	line := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b) + "\n"
	}
	logs := `C:\Windows\System32\winevt\Logs\`
	files := []struct{ name, zipped, body string }{
		{"Security.evtx", "Security.evtx", "security log bytes"},
		{"Microsoft-Windows-Sysmon%4Operational.evtx", "Microsoft-Windows-Sysmon%254Operational.evtx", "sysmon log bytes"},
	}
	var uploads, results string
	for _, f := range files {
		write("uploads/auto/C%3A/Windows/System32/winevt/Logs/"+f.zipped, f.body)
		uploads += line(map[string]any{
			"vfs_path":    logs + f.name,
			"_Components": []string{"uploads", "auto", "C:", "Windows", "System32", "winevt", "Logs", f.name},
			"file_size":   len(f.body), "uploaded_size": len(f.body),
		})
		results += line(map[string]any{"SourceFile": logs + f.name, "SourceFileSha256": sum(f.body)})
	}
	write("uploads.json", uploads)
	write("results/Generic.Collectors.File%2FUploads.json", results)
	write("collection_context.json", `{"session_id":"F.TEST","total_uploaded_files":2}`)
	write("client_info.json", `{"Hostname":"WS01","Version":"0.77.3"}`)
	write("log.json", line(map[string]any{"level": "DEFAULT", "message": "Collected 2 rows"}))
	return dir
}

func TestAWholeCollectionIsSaidToBeWhole(t *testing.T) {
	dir := build(t)
	if !Is(dir) {
		t.Fatal("not recognised as a collection")
	}
	c, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Whole() || c.Listed != 2 || c.Present != 2 || c.Hashed != 2 || c.Host != "WS01" || c.Session != "F.TEST" {
		t.Fatalf("check: %+v", c)
	}
	if got := c.Describe("case.zip"); !strings.Contains(got, "all 2 matching the SHA-256") || strings.Contains(got, "incomplete") {
		t.Errorf("described as %q", got)
	}
}

// Each way a copy can differ from what the collector made is counted, named
// and makes the collection not whole.
func TestWhatIsWrongWithACollectionIsSaid(t *testing.T) {
	sysmon := filepath.FromSlash("uploads/auto/C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%254Operational.evtx")
	cases := map[string]struct {
		damage func(t *testing.T, dir string)
		wrong  func(Check) bool
		says   string
	}{
		"altered": {
			func(t *testing.T, dir string) { rewrite(t, filepath.Join(dir, sysmon), "sysmon log BYTES") },
			func(c Check) bool {
				return c.Altered == 1 && strings.HasSuffix(c.FirstAltered, "Sysmon%4Operational.evtx")
			},
			"do not hash to what the collector recorded",
		},
		"cut short": {
			func(t *testing.T, dir string) { rewrite(t, filepath.Join(dir, sysmon), "sysmon") },
			func(c Check) bool { return c.WrongSize == 1 && c.Altered == 0 },
			"not the size the collector recorded",
		},
		"missing": {
			func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, sysmon)) },
			func(c Check) bool { return c.Present == 1 && strings.HasSuffix(c.Missing, "Sysmon%4Operational.evtx") },
			"listed file(s) are not in it",
		},
		"added": {
			func(t *testing.T, dir string) { rewrite(t, filepath.Join(dir, "uploads", "auto", "extra.evtx"), "x") },
			func(c Check) bool { return c.Unlisted == 1 && c.FirstUnlisted == "uploads/auto/extra.evtx" },
			"are not in its list",
		},
		"collector error": {
			func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "log.json"), `{"level":"ERROR","message":"access denied: Security.evtx"}`+"\n")
			},
			func(c Check) bool { return c.Errors == 1 && c.FirstError == "access denied: Security.evtx" },
			"error(s) in the collector's log",
		},
		"summary disagrees": {
			func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "collection_context.json"), `{"session_id":"F.TEST","total_uploaded_files":3}`)
			},
			func(c Check) bool { return c.ContextFiles == 3 && c.Listed == 2 },
			"counts 3 uploaded file(s) and its list has 2",
		},
		"description damaged": {
			func(t *testing.T, dir string) {
				f, _ := os.OpenFile(filepath.Join(dir, "uploads.json"), os.O_APPEND|os.O_WRONLY, 0)
				f.WriteString("{not json\n")
				f.Close()
			},
			func(c Check) bool { return c.Unreadable == 1 },
			"could not be read",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := build(t)
			tc.damage(t, dir)
			c, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if c.Whole() || !tc.wrong(c) {
				t.Fatalf("check: %+v", c)
			}
			got := c.Describe("case")
			if !strings.Contains(got, tc.says) || !strings.Contains(got, "incomplete or altered copy") {
				t.Errorf("described as %q", got)
			}
		})
	}
}

// A collection whose artifact recorded no hashes says the copy cannot be
// checked, instead of passing for one that was.
func TestNoRecordedHashIsNotAMatch(t *testing.T) {
	dir := build(t)
	os.RemoveAll(filepath.Join(dir, "results"))
	c, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hashed != 0 || !strings.Contains(c.Describe("case"), "records no hash") {
		t.Errorf("check %+v, %q", c, c.Describe("case"))
	}
}

func rewrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func zipOf(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Collection-WS01.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range entries {
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

func TestUnpackRefusesWhatIsNotAnOpenCollection(t *testing.T) {
	cases := map[string]struct {
		entries map[string]string
		says    string
	}{
		"some other zip": {map[string]string{"notes.txt": "x"}, "not a Velociraptor collection"},
		"encrypted":      {map[string]string{"data.zip": "x", "metadata.json": "{}"}, "encrypted Velociraptor collection"},
		"escaping": {map[string]string{"collection_context.json": "{}", "uploads.json": "", "../outside.evtx": "x"},
			"outside the collection"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "out")
			_, err := Unpack(zipOf(t, tc.entries), dst)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("error %v, want one saying %q", err, tc.says)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "outside.evtx")); err == nil {
				t.Error("a file was written outside the destination")
			}
		})
	}
}

func TestUnpackWritesTheCollection(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out")
	n, err := Unpack(zipOf(t, map[string]string{
		"collection_context.json":            `{"session_id":"F.TEST"}`,
		"uploads.json":                       "",
		"uploads/auto/C%3A/Logs/System.evtx": "bytes",
	}), dst)
	if err != nil || n != 3 || !Is(dst) {
		t.Fatalf("wrote %d, err %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "uploads", "auto", "C%3A", "Logs", "System.evtx")); string(b) != "bytes" {
		t.Errorf("copied file reads %q", b)
	}
}
