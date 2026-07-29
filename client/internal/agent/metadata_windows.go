//go:build windows

package agent

import (
	"os"
)

func applyTargetFileMetadata(tmpFile string, targetPath string, defaultMode os.FileMode) os.FileMode {
	info, err := os.Stat(targetPath)
	if err != nil {
		_ = os.Chmod(tmpFile, defaultMode)
		return defaultMode
	}

	mode := info.Mode().Perm()
	_ = os.Chmod(tmpFile, mode)
	return mode
}
