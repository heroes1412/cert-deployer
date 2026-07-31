package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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

func BackupFile(filePath string) (string, error) {
	if filePath == "" {
		return "", nil
	}

	info, err := os.Stat(filePath)
	if os.IsNotExist(err) || info == nil || info.IsDir() {
		return "", nil // No existing file to backup
	}

	dateStr := time.Now().Format("02012006") // DDMMYYYY
	backupPath := fmt.Sprintf("%s.%s.bak", filePath, dateStr)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file for backup %s: %w", filePath, err)
	}

	mode := info.Mode()
	if err := os.WriteFile(backupPath, data, mode); err != nil {
		return "", fmt.Errorf("failed to write backup file %s: %w", backupPath, err)
	}

	_ = applyTargetFileMetadata(backupPath, filePath, mode)

	return backupPath, nil
}

func WriteAtomicBytes(targetPath string, data []byte, defaultMode os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpFile := targetPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, defaultMode); err != nil {
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

func WriteAtomicFile(targetPath string, content string, defaultMode os.FileMode) error {
	return WriteAtomicBytes(targetPath, []byte(content), defaultMode)
}

func WritePFXFile(pfxFile string, pfxBytes []byte) error {
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	if bak, err := BackupFile(pfxFile); err == nil && bak != "" {
		fmt.Printf("[%s] [INFO] Created backup: %s -> %s\n", nowStr, pfxFile, bak)
	}

	if err := WriteAtomicBytes(pfxFile, pfxBytes, 0600); err != nil {
		return fmt.Errorf("failed writing PFX file: %w", err)
	}

	return nil
}

func WriteCertAndKey(certFile, keyFile, certPEM, keyPEM string) error {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)

	nowStr := time.Now().Format("2006-01-02 15:04:05")

	// Combined certificate case (e.g., HAProxy certfile == keyfile or empty keyfile)
	if certFile == keyFile || keyFile == "" {
		if bak, err := BackupFile(certFile); err == nil && bak != "" {
			fmt.Printf("[%s] [INFO] Created backup: %s -> %s\n", nowStr, certFile, bak)
		}
		combinedContent := certPEM + "\n" + keyPEM + "\n"
		return WriteAtomicFile(certFile, combinedContent, 0600)
	}

	// Separate cert and key files (e.g., Nginx)
	if bak, err := BackupFile(certFile); err == nil && bak != "" {
		fmt.Printf("[%s] [INFO] Created backup: %s -> %s\n", nowStr, certFile, bak)
	}
	if err := WriteAtomicFile(certFile, certPEM+"\n", 0644); err != nil {
		return fmt.Errorf("failed writing cert file: %w", err)
	}

	if bak, err := BackupFile(keyFile); err == nil && bak != "" {
		fmt.Printf("[%s] [INFO] Created backup: %s -> %s\n", nowStr, keyFile, bak)
	}
	if err := WriteAtomicFile(keyFile, keyPEM+"\n", 0600); err != nil {
		return fmt.Errorf("failed writing key file: %w", err)
	}

	return nil
}
