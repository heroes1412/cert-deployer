package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"cert-agent/internal/agent"
	"cert-agent/internal/config"

	"github.com/spf13/cobra"
)

type ServerMetaResponse struct {
	ServercertName string `json:"servercert_name"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
	Domains        string `json:"domains"`
	Error          string `json:"error"`
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check local certificate status against server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig(ConfigFile)
		if err != nil {
			return err
		}

		type TableRow struct {
			Name      string
			Domains   string
			ServerExp string
			LocalExp  string
			Status    string
		}

		client := &http.Client{Timeout: 10 * time.Second}
		now := time.Now()
		var rows []TableRow

		for _, cert := range cfg.Certs {
			row := TableRow{
				Name:      cert.ServercertName,
				Domains:   "N/A",
				ServerExp: "N/A",
				LocalExp:  "N/A",
				Status:    "PENDING",
			}

			// Read local certificate expiration (Prioritize PfxFile if configured)
			var localCertTime *time.Time
			if cert.PfxFile != "" && fileExists(cert.PfxFile) {
				t, err := agent.GetPFXCertNotAfter(cert.PfxFile, cert.PfxPassword)
				if err == nil && t != nil {
					localCertTime = t
				}
			} else if cert.CertFile != "" && fileExists(cert.CertFile) {
				certData, err := os.ReadFile(cert.CertFile)
				if err == nil {
					block, _ := pem.Decode(certData)
					if block != nil && block.Type == "CERTIFICATE" {
						parsedCert, err := x509.ParseCertificate(block.Bytes)
						if err == nil {
							t := parsedCert.NotAfter
							localCertTime = &t
						}
					}
				}
			}

			if localCertTime != nil {
				days := int(math.Ceil(localCertTime.Sub(now).Hours() / 24))
				if days < 0 {
					row.LocalExp = fmt.Sprintf("%s (EXPIRED)", localCertTime.Format("2006-01-02"))
				} else {
					row.LocalExp = fmt.Sprintf("%s (%dd)", localCertTime.Format("2006-01-02"), days)
				}
			}

			// Fetch server metadata
			reqURL := fmt.Sprintf("%s/api/v1/certs/%s/meta", cfg.ServerURL, cert.ServercertName)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
				resp, err := client.Do(req)
				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					if resp.StatusCode == http.StatusUnauthorized {
						row.Status = "INVALID TOKEN"
					} else if resp.StatusCode == http.StatusForbidden {
						row.Status = "FORBIDDEN"
					} else if resp.StatusCode == http.StatusNotFound {
						row.Status = "SERVER NOT FOUND"
					} else if resp.StatusCode == http.StatusOK {
						var meta ServerMetaResponse
						if err := json.Unmarshal(body, &meta); err == nil && meta.NotAfter != "" {
							if meta.Domains != "" {
								row.Domains = meta.Domains
							}
							t, err := time.Parse("2006-01-02T15:04:05Z", meta.NotAfter)
							if err == nil {
								days := int(math.Ceil(t.Sub(now).Hours() / 24))
								if days < 0 {
									row.ServerExp = fmt.Sprintf("%s (EXPIRED)", t.Format("2006-01-02"))
								} else {
									row.ServerExp = fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), days)
								}

								if localCertTime == nil {
									row.Status = "LOCAL NOT FOUND"
								} else if t.After(*localCertTime) {
									row.Status = "UPDATE AVAIL"
								} else {
									row.Status = "UP TO DATE"
								}
							}
						}
					} else {
						row.Status = fmt.Sprintf("HTTP %d", resp.StatusCode)
					}
				} else {
					row.Status = "CONN ERR"
				}
			} else {
				row.Status = "CONN ERR"
			}

			rows = append(rows, row)
		}

		// Print ASCII Table: SERVERCERT NAME | DOMAINS / SANS | SERVER EXPIRATION | LOCAL EXPIRATION | STATUS
		fmt.Println("+-----------------+-------------------------------------+---------------------+---------------------+------------------+")
		fmt.Println("| SERVERCERT NAME | DOMAINS / SANS                      | SERVER EXPIRATION   | LOCAL EXPIRATION    | STATUS           |")
		fmt.Println("+-----------------+-------------------------------------+---------------------+---------------------+------------------+")
		for _, r := range rows {
			domStr := r.Domains
			parts := strings.Split(r.Domains, ",")
			if len(parts) > 1 && len(domStr) > 35 {
				domStr = fmt.Sprintf("%s (+%d SANs)", strings.TrimSpace(parts[0]), len(parts)-1)
			}
			fmt.Printf("| %-15s | %-35s | %-19s | %-19s | %-16s |\n",
				truncateStr(r.Name, 15),
				truncateStr(domStr, 35),
				truncateStr(r.ServerExp, 19),
				truncateStr(r.LocalExp, 19),
				truncateStr(r.Status, 16),
			)
		}
		fmt.Println("+-----------------+-------------------------------------+---------------------+---------------------+------------------+")

		var certNames []string
		for _, c := range cfg.Certs {
			certNames = append(certNames, c.ServercertName)
		}
		sendAgentHeartbeat(cfg.ServerURL, cfg.AuthToken, certNames)

		return nil
	},
}

func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
