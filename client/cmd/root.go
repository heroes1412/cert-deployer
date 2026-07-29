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
