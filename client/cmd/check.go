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
	"time"

	"cert-agent/internal/config"

	"github.com/spf13/cobra"
)

type ServerMetaResponse struct {
	ServercertName string `json:"servercert_name"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
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
			Name         string
			LocalExp     string
			ServerExp    string
			Status       string
			ServerSHA256 string
			LocalSHA256  string
		}

		var rows []TableRow
		client := &http.Client{Timeout: 10 * time.Second}
		now := time.Now()

		for _, cert := range cfg.Certs {
			row := TableRow{
				Name:      cert.ServercertName,
				LocalExp:  "N/A",
				ServerExp: "N/A",
				Status:    "UNKNOWN",
			}

			// Read local certificate expiration
			var localCertTime *time.Time
			if cert.CertFile != "" {
				certData, err := os.ReadFile(cert.CertFile)
				if err == nil {
					block, _ := pem.Decode(certData)
					if block != nil && block.Type == "CERTIFICATE" {
						parsedCert, err := x509.ParseCertificate(block.Bytes)
						if err == nil {
							t := parsedCert.NotAfter
							localCertTime = &t
							days := int(math.Ceil(t.Sub(now).Hours() / 24))
							row.LocalExp = fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), days)
						}
					}
				}
			}

			// Fetch server metadata
			reqURL := fmt.Sprintf("%s/api/v1/certs/%s/meta", cfg.ServerURL, cert.ServercertName)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
				resp, err := client.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					var meta ServerMetaResponse
					if err := json.Unmarshal(body, &meta); err == nil && meta.NotAfter != "" {
						t, err := time.Parse("2006-01-02T15:04:05Z", meta.NotAfter)
						if err == nil {
							days := int(math.Ceil(t.Sub(now).Hours() / 24))
							row.ServerExp = fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), days)
							row.ServerSHA256 = meta.SHA256

							if localCertTime == nil {
								row.Status = "MISSING LOCAL"
							} else if t.After(*localCertTime) {
								row.Status = "UPDATE AVAIL"
							} else {
								row.Status = "UP TO DATE"
							}
						}
					}
				} else {
					row.Status = "SERVER ERR"
				}
			} else {
				row.Status = "CONN ERR"
			}

			rows = append(rows, row)
		}

		// Print ASCII Table
		fmt.Println("+-----------------+---------------------+---------------------+----------------+")
		fmt.Println("| SERVERCERT NAME | LOCAL EXPIRATION    | SERVER EXPIRATION   | STATUS         |")
		fmt.Println("+-----------------+---------------------+---------------------+----------------+")
		for _, r := range rows {
			fmt.Printf("| %-15s | %-19s | %-19s | %-14s |\n",
				truncateStr(r.Name, 15),
				truncateStr(r.LocalExp, 19),
				truncateStr(r.ServerExp, 19),
				truncateStr(r.Status, 14),
			)
		}
		fmt.Println("+-----------------+---------------------+---------------------+----------------+")

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
