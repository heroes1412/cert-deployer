package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type CertMapping struct {
	ServercertName string `yaml:"servercert_name"`
	CertFile       string `yaml:"certfile"`
	KeyFile        string `yaml:"keyfile"`
	PfxFile        string `yaml:"pfxfile"`
	PfxPassword    string `yaml:"pfx_password"`
	IISSiteName    string `yaml:"iis_site_name"`
	IISBindingHost string `yaml:"iis_binding_host"`
	PreCmd         string `yaml:"pre_cmd"`
	PostCmd        string `yaml:"post_cmd"`
}

type Config struct {
	ServerURL     string        `yaml:"server_url"`
	AuthToken     string        `yaml:"auth_token"`
	GlobalPreCmd  string        `yaml:"global_pre_cmd"`
	Certs         []CertMapping `yaml:"certs"`
	GlobalPostCmd string        `yaml:"global_post_cmd"`
}

// preprocessYAML escapes single backslashes in double-quoted strings (e.g. "C:\path", "copy nul c:\file")
// into double backslashes "\\", ensuring YAML parsing succeeds without corrupting backslashes into '/'
// or breaking shell commands (like cmd.exe copy) or turning \t/\n into control characters.
func preprocessYAML(data []byte) []byte {
	var buf bytes.Buffer
	inDoubleQuotes := false

	for i := 0; i < len(data); i++ {
		ch := data[i]

		// Track double quote boundaries
		if ch == '"' {
			bsCount := 0
			for j := i - 1; j >= 0 && data[j] == '\\'; j-- {
				bsCount++
			}
			if bsCount%2 == 0 {
				inDoubleQuotes = !inDoubleQuotes
			}
			buf.WriteByte(ch)
			continue
		}

		if inDoubleQuotes && ch == '\\' {
			// If already double backslash \\, keep \\
			if i+1 < len(data) && data[i+1] == '\\' {
				buf.WriteString("\\\\")
				i++ // skip second backslash
				continue
			}
			// If escaped double quote \", keep \"
			if i+1 < len(data) && data[i+1] == '"' {
				buf.WriteString("\\\"")
				i++ // skip quote
				continue
			}
			// Escape single backslash inside double quotes to \\ so YAML unmarshals literal \
			buf.WriteString("\\\\")
			continue
		}

		buf.WriteByte(ch)
	}

	return buf.Bytes()
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file at %s: %w", path, err)
	}

	cleanedData := preprocessYAML(data)

	var cfg Config
	if err := yaml.Unmarshal(cleanedData, &cfg); err != nil {
		return nil, fmt.Errorf("unable to parse YAML config: %w", err)
	}

	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	// Support reading Auth Token from environment variable CERT_AGENT_TOKEN
	if envToken := strings.TrimSpace(os.Getenv("CERT_AGENT_TOKEN")); envToken != "" {
		cfg.AuthToken = envToken
	}

	for i := range cfg.Certs {
		if cfg.Certs[i].CertFile != "" {
			cfg.Certs[i].CertFile = filepath.Clean(cfg.Certs[i].CertFile)
		}
		if cfg.Certs[i].KeyFile != "" {
			cfg.Certs[i].KeyFile = filepath.Clean(cfg.Certs[i].KeyFile)
		}
		if cfg.Certs[i].PfxFile != "" {
			cfg.Certs[i].PfxFile = filepath.Clean(cfg.Certs[i].PfxFile)
		}
	}

	return &cfg, nil
}

func (c *Config) ValidateTargetDirectories() error {
	for _, cert := range c.Certs {
		if cert.CertFile != "" {
			dir := filepath.Dir(cert.CertFile)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return fmt.Errorf("target directory does not exist for certfile %s: %s", cert.CertFile, dir)
			}
		}
		if cert.KeyFile != "" {
			dir := filepath.Dir(cert.KeyFile)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return fmt.Errorf("target directory does not exist for keyfile %s: %s", cert.KeyFile, dir)
			}
		}
		if cert.PfxFile != "" {
			dir := filepath.Dir(cert.PfxFile)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return fmt.Errorf("target directory does not exist for pfxfile %s: %s", cert.PfxFile, dir)
			}
		}
	}
	return nil
}
