package utils

import (
	"path/filepath"
)

// FixupPathIfRelative returns an absolute path which is either the same as p,
// if that is absolute, or uses rel as base and combines that with p.
func FixupPathIfRelative(p string, rel string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(rel), p)
}
