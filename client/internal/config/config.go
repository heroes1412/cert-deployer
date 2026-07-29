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
	PreCmd         string `yaml:"pre_cmd"`
	PostCmd        string `yaml:"post_cmd"`
}

type Config struct {
	ServerURL     string        `yaml:"server_url"`
	AuthToken     string        `yaml:"auth_token"`
	GlobalPreCmd  string        `yaml:"global_pre_cmd"`
	PreCmd        string        `yaml:"pre_cmd"`
	Certs         []CertMapping `yaml:"certs"`
	GlobalPostCmd string        `yaml:"global_post_cmd"`
	PostCmd       string        `yaml:"post_cmd"`
}

func (c *Config) GetGlobalPreCmd() string {
	if strings.TrimSpace(c.GlobalPreCmd) != "" {
		return c.GlobalPreCmd
	}
	return c.PreCmd
}

func (c *Config) GetGlobalPostCmd() string {
	if strings.TrimSpace(c.GlobalPostCmd) != "" {
		return c.GlobalPostCmd
	}
	return c.PostCmd
}

// preprocessYAML cleans invalid Windows backslash escapes (e.g. \v, \i, \L, \S, \e, \p)
// by replacing single backslashes in path strings with forward slashes before parsing.
func preprocessYAML(data []byte) []byte {
	var buf bytes.Buffer
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(data); i++ {
		ch := data[i]

		if (ch == '"' || ch == '\'') && (i == 0 || data[i-1] != '\\') {
			if !inQuote {
				inQuote = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuote = false
			}
			buf.WriteByte(ch)
			continue
		}

		if ch == '\\' {
			if i+1 < len(data) {
				next := data[i+1]
				// Keep valid standard YAML escapes: \n, \t, \r, \", \\
				if next == 'n' || next == 't' || next == 'r' || next == '"' || next == '\\' {
					buf.WriteByte('\\')
					buf.WriteByte(next)
					i++
					continue
				}
			}
			// Convert invalid backslash escape to forward slash
			buf.WriteByte('/')
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

	for i := range cfg.Certs {
		cfg.Certs[i].CertFile = filepath.ToSlash(cfg.Certs[i].CertFile)
		cfg.Certs[i].KeyFile = filepath.ToSlash(cfg.Certs[i].KeyFile)
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
	}
	return nil
}
