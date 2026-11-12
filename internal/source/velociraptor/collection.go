// Package velociraptor reads what a Velociraptor collection says about itself.
//
// A collection is a folder, usually still zipped, with the files it copied
// under uploads/ and a handful of JSON files describing the copy: what was
// asked for, what was uploaded and how large, what the collector logged. The
// evidence is the copied files, read by the readers for their own formats.
// This package reads the description, so a report over a collection can say
// whether the copy it analysed is the copy the collector made.
//
// The layout is the one written by Velociraptor 0.77.3's offline collector,
// taken from a collection of one Windows machine and not from documentation.
package velociraptor

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	contextFile = "collection_context.json"
	uploadsFile = "uploads.json"
	uploadsDir  = "uploads"
)

// Is says whether dir is the top of a collection.
func Is(dir string) bool {
	for _, name := range []string{contextFile, uploadsFile} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

// Evidence says whether path, inside the collection at dir, is one of the
// copied files. Everything else in a collection describes the copy.
func Evidence(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(filepath.ToSlash(rel), uploadsDir+"/")
}

// Check is the collection's account of itself set against the files on disk.
type Check struct {
	Session string
	Host    string
	Version string

	// Listed is the files uploads.json says were copied; Present, how many of
	// them are on disk; Missing, the first that is not.
	Listed  int
	Present int
	Missing string

	// Unlisted is files under uploads/ that uploads.json does not mention.
	Unlisted      int
	FirstUnlisted string

	// Truncated is files the collector itself says it copied short.
	Truncated      int
	FirstTruncated string

	// WrongSize is files whose size on disk is not the size recorded.
	WrongSize      int
	FirstWrongSize string

	// Hashed is files the collection carries a SHA-256 for; Altered, those
	// whose bytes on disk hash to something else.
	Hashed       int
	Altered      int
	FirstAltered string

	// ContextFiles is the count in collection_context.json, -1 when absent.
	ContextFiles int

	// Errors is the collector's own log lines at ERROR level.
	Errors     int
	FirstError string

	// Unreadable is lines of the description that are not JSON.
	Unreadable int
}

// Whole says whether nothing in the check contradicts the collection being
// the one the collector wrote.
func (c Check) Whole() bool {
	return c.Present == c.Listed && c.Unlisted == 0 && c.Truncated == 0 && c.WrongSize == 0 &&
		c.Altered == 0 && c.Errors == 0 && c.Unreadable == 0 &&
		(c.ContextFiles < 0 || c.ContextFiles == c.Listed)
}

type upload struct {
	VFSPath    string   `json:"vfs_path"`
	Components []string `json:"_Components"`
	FileSize   int64    `json:"file_size"`
	Uploaded   int64    `json:"uploaded_size"`
}

// Verify reads the description of the collection at dir and compares it with
// the files under uploads/. Every copied file is read once to hash it.
func Verify(dir string) (Check, error) {
	c := Check{ContextFiles: -1}

	var ctx struct {
		Session string `json:"session_id"`
		Files   *int   `json:"total_uploaded_files"`
	}
	if err := readJSON(filepath.Join(dir, contextFile), &ctx); err != nil {
		return c, err
	}
	c.Session = ctx.Session
	if ctx.Files != nil {
		c.ContextFiles = *ctx.Files
	}
	var client struct {
		Hostname string `json:"Hostname"`
		Version  string `json:"Version"`
	}
	// client_info.json is not in every collection; without it the host is
	// simply not stated here.
	if err := readJSON(filepath.Join(dir, "client_info.json"), &client); err == nil {
		c.Host, c.Version = client.Hostname, client.Version
	}

	// What is on disk, keyed the way uploads.json names it: the collector
	// escapes each path segment (C: is C%3A, a % in a name is %25).
	onDisk := map[string]string{}
	top := filepath.Join(dir, uploadsDir)
	err := filepath.WalkDir(top, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for i, p := range parts {
			if u, err := url.PathUnescape(p); err == nil {
				parts[i] = u
			}
		}
		onDisk[strings.Join(parts, "/")] = path
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return c, err
	}

	hashes, bad, err := recordedHashes(dir)
	if err != nil {
		return c, err
	}
	c.Unreadable += bad

	listed := map[string]bool{}
	bad, err = eachLine(filepath.Join(dir, uploadsFile), func(line []byte) bool {
		var u upload
		if json.Unmarshal(line, &u) != nil || len(u.Components) == 0 {
			return false
		}
		c.Listed++
		key := strings.Join(u.Components, "/")
		listed[key] = true
		if u.Uploaded != u.FileSize {
			c.Truncated++
			first(&c.FirstTruncated, u.VFSPath)
		}
		path, ok := onDisk[key]
		if !ok {
			first(&c.Missing, u.VFSPath)
			return true
		}
		c.Present++
		size, sum, err := hashFile(path)
		if err != nil || size != u.Uploaded {
			c.WrongSize++
			first(&c.FirstWrongSize, u.VFSPath)
			return true
		}
		if want, ok := hashes[u.VFSPath]; ok {
			c.Hashed++
			if !strings.EqualFold(want, sum) {
				c.Altered++
				first(&c.FirstAltered, u.VFSPath)
			}
		}
		return true
	})
	if err != nil {
		return c, err
	}
	c.Unreadable += bad
	for key := range onDisk {
		if !listed[key] {
			c.Unlisted++
			if c.FirstUnlisted == "" || key < c.FirstUnlisted {
				c.FirstUnlisted = key
			}
		}
	}

	bad, err = eachLine(filepath.Join(dir, "log.json"), func(line []byte) bool {
		var l struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		if json.Unmarshal(line, &l) != nil {
			return false
		}
		if strings.EqualFold(l.Level, "ERROR") {
			c.Errors++
			first(&c.FirstError, strings.TrimSpace(l.Message))
		}
		return true
	})
	if err != nil && !os.IsNotExist(err) {
		return c, err
	}
	c.Unreadable += bad
	return c, nil
}

// recordedHashes collects the SHA-256 the collector wrote for each file it
// copied. They are in the results of the artifact that did the copying
// (results/<artifact>%2FUploads.json, SourceFile and SourceFileSha256), and an
// artifact that records none leaves the map empty.
func recordedHashes(dir string) (map[string]string, int, error) {
	out := map[string]string{}
	bad := 0
	names, err := filepath.Glob(filepath.Join(dir, "results", "*Uploads.json"))
	if err != nil {
		return out, 0, err
	}
	for _, name := range names {
		n, err := eachLine(name, func(line []byte) bool {
			var r struct {
				Source string `json:"SourceFile"`
				Sum    string `json:"SourceFileSha256"`
			}
			if json.Unmarshal(line, &r) != nil {
				return false
			}
			if r.Source != "" && r.Sum != "" {
				out[r.Source] = r.Sum
			}
			return true
		})
		if err != nil {
			return out, bad, err
		}
		bad += n
	}
	return out, bad, nil
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("%s: %v", filepath.Base(path), err)
	}
	return nil
}

// eachLine hands every non-empty line to fn and counts those it refuses.
func eachLine(path string, fn func([]byte) bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	bad := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if !fn(line) {
			bad++
		}
	}
	return bad, sc.Err()
}

func first(into *string, v string) {
	if *into == "" {
		*into = v
	}
}

// Describe writes the check as the sentence a report carries.
func (c Check) Describe(name string) string {
	who := "Velociraptor collection " + name
	if c.Host != "" {
		who += " of " + c.Host
	}
	if c.Session != "" {
		who += " (" + c.Session + ")"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d file(s) listed as copied, %d present", who, c.Listed, c.Present)
	switch {
	case c.Hashed == 0:
		b.WriteString("; the collection records no hash for them, so the copy cannot be checked against what the collector read")
	case c.Altered == 0 && c.Hashed == c.Present:
		fmt.Fprintf(&b, ", all %d matching the SHA-256 the collector recorded", c.Hashed)
	default:
		fmt.Fprintf(&b, ", %d of %d with a recorded SHA-256 matching it", c.Hashed-c.Altered, c.Hashed)
	}
	b.WriteString(".")
	problem := func(n int, what, example string) {
		if n > 0 {
			fmt.Fprintf(&b, " %d %s (first: %s).", n, what, example)
		}
	}
	problem(c.Listed-c.Present, "listed file(s) are not in it", c.Missing)
	problem(c.Altered, "file(s) do not hash to what the collector recorded", c.FirstAltered)
	problem(c.WrongSize, "file(s) are not the size the collector recorded", c.FirstWrongSize)
	problem(c.Truncated, "file(s) were copied short by the collector's own account", c.FirstTruncated)
	problem(c.Unlisted, "file(s) under uploads/ are not in its list", c.FirstUnlisted)
	problem(c.Errors, "error(s) in the collector's log", c.FirstError)
	if c.ContextFiles >= 0 && c.ContextFiles != c.Listed {
		fmt.Fprintf(&b, " Its summary counts %d uploaded file(s) and its list has %d.", c.ContextFiles, c.Listed)
	}
	if c.Unreadable > 0 {
		fmt.Fprintf(&b, " %d line(s) of its description could not be read.", c.Unreadable)
	}
	if !c.Whole() {
		b.WriteString(" What this report says about that machine is over an incomplete or altered copy.")
	}
	return b.String()
}
