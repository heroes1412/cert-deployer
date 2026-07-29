package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"cert-agent/internal/agent"
	"cert-agent/internal/config"

	"github.com/spf13/cobra"
)

type ServerCertResponse struct {
	ServercertName string `json:"servercert_name"`
	CertPEM        string `json:"cert_pem"`
	KeyPEM         string `json:"key_pem"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
	Error          string `json:"error"`
}

func logInfo(format string, a ...interface{}) {
	fmt.Printf("[%s] [INFO] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
}

func logWarn(format string, a ...interface{}) {
	fmt.Printf("[%s] [WARN] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
}

func logError(format string, a ...interface{}) {
	fmt.Printf("[%s] [ERROR] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) || info == nil || info.IsDir() {
		return false
	}
	return true
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize certificates from Cert Vault Server",
	RunE: func(cmd *cobra.Command, args []string) error {
		logInfo("Starting certificate synchronization agent...")

		cfg, err := config.LoadConfig(ConfigFile)
		if err != nil {
			logError("Failed to load configuration: %v", err)
			return err
		}

		// 1. Run global_pre_cmd / pre_cmd
		globalPre := cfg.GetGlobalPreCmd()
		if globalPre != "" {
			logInfo("Running global pre_cmd: %s", globalPre)
			out, err := agent.ExecuteCommand(globalPre, 30*time.Second)
			if err != nil {
				logError("Global pre_cmd failed: %v. Aborting update!", err)
				os.Exit(1)
			}
			if out != "" {
				logInfo("Global pre_cmd output: %s", out)
			}
		}

		// 2. Sync Certificates
		updatedCount := 0
		httpClient := &http.Client{Timeout: 15 * time.Second}

		for _, cert := range cfg.Certs {
			logInfo("Processing cert mapping: %s", cert.ServercertName)

			// Check local file existence before attempting sync
			if !fileExists(cert.CertFile) {
				logWarn("Local certfile does not exist (%s) for %s. Skipping cert update.", cert.CertFile, cert.ServercertName)
				continue
			}
			if cert.KeyFile != "" && cert.KeyFile != cert.CertFile && !fileExists(cert.KeyFile) {
				logWarn("Local keyfile does not exist (%s) for %s. Skipping cert update.", cert.KeyFile, cert.ServercertName)
				continue
			}

			// Per-cert pre_cmd
			if cert.PreCmd != "" {
				logInfo("Running per-cert pre_cmd for %s: %s", cert.ServercertName, cert.PreCmd)
				out, err := agent.ExecuteCommand(cert.PreCmd, 30*time.Second)
				if err != nil {
					logError("Per-cert pre_cmd failed for %s: %v. Skipping cert update.", cert.ServercertName, err)
					continue
				}
				if out != "" {
					logInfo("Per-cert pre_cmd output for %s: %s", cert.ServercertName, out)
				}
			}

			reqURL := fmt.Sprintf("%s/api/v1/certs/%s", cfg.ServerURL, cert.ServercertName)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				logError("Failed to create HTTP request for %s: %v", cert.ServercertName, err)
				continue
			}
			req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)

			resp, err := httpClient.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				status := "CONN_ERR"
				if resp != nil {
					if resp.StatusCode == http.StatusNotFound {
						status = "HTTP 404 (Not Found)"
					} else {
						status = fmt.Sprintf("HTTP %d", resp.StatusCode)
					}
				}
				logError("Failed to fetch cert %s from server: %s", cert.ServercertName, status)
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var certResp ServerCertResponse
			if err := json.Unmarshal(body, &certResp); err != nil || certResp.CertPEM == "" {
				logError("Invalid JSON response from server for %s", cert.ServercertName)
				continue
			}

			// Check local SHA256 against server SHA256
			localSHA, err := agent.ComputeFileSHA256(cert.CertFile)
			if err == nil && localSHA == certResp.SHA256 {
				logInfo("Certificate %s is already up to date (SHA256: %s). Skipping download.", cert.ServercertName, localSHA[:16])
				continue
			}

			logInfo("Certificate update detected for %s. Writing updated files...", cert.ServercertName)
			if err := agent.WriteCertAndKey(cert.CertFile, cert.KeyFile, certResp.CertPEM, certResp.KeyPEM); err != nil {
				logError("Failed to write cert/key files for %s: %v", cert.ServercertName, err)
				continue
			}

			logInfo("Successfully updated certificate files for %s", cert.ServercertName)
			updatedCount++

			// Per-cert post_cmd
			if cert.PostCmd != "" {
				logInfo("Running per-cert post_cmd for %s: %s", cert.ServercertName, cert.PostCmd)
				out, err := agent.ExecuteCommand(cert.PostCmd, 30*time.Second)
				if err != nil {
					logError("Per-cert post_cmd failed for %s: %v", cert.ServercertName, err)
				} else if out != "" {
					logInfo("Per-cert post_cmd output for %s: %s", cert.ServercertName, out)
				}
			}
		}

		logInfo("Synchronization complete. Total certificates updated: %d", updatedCount)

		// 3. Run global_post_cmd / post_cmd if at least one cert was updated
		globalPost := cfg.GetGlobalPostCmd()
		if updatedCount > 0 && globalPost != "" {
			logInfo("Running global post_cmd: %s", globalPost)
			out, err := agent.ExecuteCommand(globalPost, 30*time.Second)
			if err != nil {
				logError("Global post_cmd failed after cert update!: %v", err)
			} else if out != "" {
				logInfo("Global post_cmd output: %s", out)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
}
