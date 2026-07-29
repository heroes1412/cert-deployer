package config

import (
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
}

type Config struct {
	ServerURL string        `yaml:"server_url"`
	AuthToken string        `yaml:"auth_token"`
	PreCmd    string        `yaml:"pre_cmd"`
	Certs     []CertMapping `yaml:"certs"`
	PostCmd   string        `yaml:"post_cmd"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file at %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unable to parse YAML config: %w", err)
	}

	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
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
