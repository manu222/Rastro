package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/manu222/rastro/internal/source/velociraptor"
)

// openEvidence resolves what an analysis was pointed at: a directory, or a
// Velociraptor collection still in its zip, which is how a collector leaves
// it. The archive is unpacked into a temporary directory under its own name,
// so every record's origin reads Collection-HOST-date.zip/uploads/..., and
// done removes it.
func openEvidence(path string) (root string, done func(), err error) {
	done = func() {}
	info, serr := os.Stat(path)
	if serr != nil || info.IsDir() || !velociraptor.IsArchive(path) {
		root, err = evidenceRoot(path)
		return root, done, err
	}
	tmp, err := os.MkdirTemp("", "rastro-")
	if err != nil {
		return "", done, err
	}
	done = func() { os.RemoveAll(tmp) }
	if _, err := velociraptor.Unpack(path, filepath.Join(tmp, filepath.Base(path))); err != nil {
		done()
		return "", func() {}, err
	}
	root, err = evidenceRoot(tmp)
	if err != nil {
		done()
		return "", func() {}, err
	}
	return root, done, nil
}

// collectionsAmong finds the Velociraptor collections in a list of files, by
// the directory that holds their description.
func collectionsAmong(files []string) []string {
	var out []string
	for _, f := range files {
		if filepath.Base(f) == "collection_context.json" && velociraptor.Is(filepath.Dir(f)) {
			out = append(out, filepath.Dir(f))
		}
	}
	sort.Strings(out)
	return out
}

// withoutDescriptions drops the files of a collection that describe the copy.
// They are JSON, and read as evidence each of their lines was a record with no
// provider: 1,659 unreadable records over a collection whose 414,647 real ones
// were all read.
func withoutDescriptions(files []string) []string {
	collections := collectionsAmong(files)
	if len(collections) == 0 {
		return files
	}
	kept := files[:0:0]
	for _, f := range files {
		drop := false
		for _, c := range collections {
			if strings.HasPrefix(f, c+string(filepath.Separator)) && !velociraptor.Evidence(c, f) {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, f)
		}
	}
	return kept
}

// collectionNotes is what the report says about each collection, and about
// archives lying in the evidence that nobody opened.
func collectionNotes(root string, files []string) []string {
	var notes []string
	for _, dir := range collectionsAmong(files) {
		name := relTo(root, dir)
		if name == "." {
			name = filepath.Base(dir)
		}
		check, err := velociraptor.Verify(dir)
		if err != nil {
			notes = append(notes, fmt.Sprintf(
				"Velociraptor collection %s: its description could not be read (%v), so the copy was not checked.", name, err))
			continue
		}
		notes = append(notes, check.Describe(name))
	}
	var closed []string
	for _, f := range files {
		if velociraptor.IsArchive(f) {
			closed = append(closed, relTo(root, f))
		}
	}
	if len(closed) > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d archive(s) in the evidence were not opened and nothing in them was read: %s. "+
				"Unpack them, or point the analysis at a Velociraptor collection's zip directly.",
			len(closed), strings.Join(closed, ", ")))
	}
	return notes
}
