package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ConfigFile string

var rootCmd = &cobra.Command{
	Use:   "cert-agent",
	Short: "Certificate Auto Rotation Agent",
	Long:  `A lightweight CLI Agent for synchronizing SSL/TLS certificates from Cert Vault Server.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&ConfigFile, "config", "c", "/etc/cert-agent/config.yaml", "path to config.yaml")
}
