package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

var ConfigFile string

var rootCmd = &cobra.Command{
	Use:   "cert-agent",
	Short: "Cert Agent - Certificate Synchronization CLI Tool",
	Long:  `Cert Agent: A lightweight CLI Agent for synchronizing SSL/TLS certificates from Cert Server.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// If user did not pass -c / --config explicitly
		if !cmd.Flags().Changed("config") {
			if _, err := os.Stat("config.yaml"); err == nil {
				ConfigFile = "config.yaml"
			} else {
				ConfigFile = "/etc/cert-agent/config.yaml"
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&ConfigFile, "config", "c", "config.yaml", "path to config.yaml")
}

type HeartbeatPayload struct {
	Hostname    string   `json:"hostname"`
	IPAddress   string   `json:"ip_address"`
	OS          string   `json:"os"`
	SyncedCerts []string `json:"synced_certs"`
}

func sendAgentHeartbeat(serverURL, authToken string, syncedCerts []string) {
	if serverURL == "" || authToken == "" {
		return
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	osInfo := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	payload := HeartbeatPayload{
		Hostname:    hostname,
		OS:          osInfo,
		SyncedCerts: syncedCerts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	reqURL := fmt.Sprintf("%s/api/v1/agent/heartbeat", serverURL)
	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}
