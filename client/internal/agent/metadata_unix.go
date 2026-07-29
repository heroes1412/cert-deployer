//go:build !windows

package agent

import (
	"os"
	"syscall"
)

func applyTargetFileMetadata(tmpFile string, targetPath string, defaultMode os.FileMode) os.FileMode {
	info, err := os.Stat(targetPath)
	if err != nil {
		_ = os.Chmod(tmpFile, defaultMode)
		return defaultMode
	}

	mode := info.Mode().Perm()
	_ = os.Chmod(tmpFile, mode)

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmpFile, int(stat.Uid), int(stat.Gid))
	}

	return mode
}
