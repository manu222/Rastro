package velociraptor

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unpack writes the collection in the archive at path under dst and returns
// how many files it wrote.
//
// An archive that is not a collection is refused before anything is written:
// a zip of something else, analysed as an empty folder, would be a report of
// nothing found over evidence that was never opened. So is an encrypted one,
// which holds a single data.zip this tool has no key for, and an entry whose
// name would land outside dst.
func Unpack(path, dst string) (int, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", filepath.Base(path), err)
	}
	defer z.Close()

	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
	}
	if !names[contextFile] || !names[uploadsFile] {
		if names["data.zip"] {
			return 0, fmt.Errorf("%s is an encrypted Velociraptor collection; decrypt it first, this tool has no key for it", filepath.Base(path))
		}
		return 0, fmt.Errorf("%s is not a Velociraptor collection: it has no %s and %s at its top", filepath.Base(path), contextFile, uploadsFile)
	}

	written := 0
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.FromSlash(f.Name)
		if !filepath.IsLocal(name) {
			return written, fmt.Errorf("%s: entry %q would be written outside the collection", filepath.Base(path), f.Name)
		}
		if f.Flags&0x1 != 0 {
			return written, fmt.Errorf("%s: entry %q is encrypted", filepath.Base(path), f.Name)
		}
		target := filepath.Join(dst, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return written, err
		}
		if err := writeEntry(f, target); err != nil {
			return written, fmt.Errorf("%s: %s: %v", filepath.Base(path), f.Name, err)
		}
		written++
	}
	return written, nil
}

func writeEntry(f *zip.File, target string) error {
	in, err := f.Open()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	// The copy fails on a bad CRC, so a damaged entry is an error here and
	// not a short file read later as a short log.
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// IsArchive says whether path looks like a zip by name. What is inside is
// decided by Unpack.
func IsArchive(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".zip")
}
