package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ComputeFileSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	// Trim space for consistent SHA256 comparison
	hash := sha256.Sum256([]byte(strings.TrimSpace(string(data))))
	return hex.EncodeToString(hash[:]), nil
}

func ComputeStringSHA256(content string) string {
	hash := sha256.Sum256([]byte(strings.TrimSpace(content)))
	return hex.EncodeToString(hash[:])
}

func WriteAtomicFile(targetPath string, content string, defaultMode os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpFile := targetPath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(content), defaultMode); err != nil {
		return fmt.Errorf("failed to write temporary file %s: %w", tmpFile, err)
	}

	// Preserve existing file permissions (mode) and owner (UID/GID on Unix) if file exists
	_ = applyTargetFileMetadata(tmpFile, targetPath, defaultMode)

	if err := os.Rename(tmpFile, targetPath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomically rename %s to %s: %w", tmpFile, targetPath, err)
	}

	return nil
}

func WriteCertAndKey(certFile, keyFile, certPEM, keyPEM string) error {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)

	// Combined certificate case (e.g., HAProxy certfile == keyfile or empty keyfile)
	if certFile == keyFile || keyFile == "" {
		combinedContent := certPEM + "\n" + keyPEM + "\n"
		return WriteAtomicFile(certFile, combinedContent, 0600)
	}

	// Separate cert and key files (e.g., Nginx)
	if err := WriteAtomicFile(certFile, certPEM+"\n", 0644); err != nil {
		return fmt.Errorf("failed writing cert file: %w", err)
	}

	if err := WriteAtomicFile(keyFile, keyPEM+"\n", 0600); err != nil {
		return fmt.Errorf("failed writing key file: %w", err)
	}

	return nil
}
