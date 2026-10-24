package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Installer files use Go/Bash value quoting, not executable shell syntax.
func loadServerRuntimeConfig(path, passwordPath string) (serverEnvConfig, error) {
	cfg, err := loadServerEnvConfig(path)
	if err != nil {
		return cfg, err
	}
	if passwordPath == "" {
		passwordPath = filepath.Join(filepath.Dir(path), "server.password")
	}
	if _, err := os.Stat(passwordPath); err == nil {
		cfg.Password, err = resolveServerPassword("", passwordPath)
		if err != nil {
			return cfg, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cfg, err
	}
	if err := validateListen(cfg.Listen); err != nil {
		return cfg, err
	}
	if cfg.Password == "" || hasControlChars(cfg.Password) {
		return cfg, errors.New("invalid server password")
	}
	return cfg, nil
}

func serverConfigRuntimeArgs(cfg serverEnvConfig) []string {
	args := []string{"-l", cfg.Listen, "-p", cfg.Password}
	for _, pair := range [][2]string{{"--cert-dir", cfg.CertDir}, {"--cert-file", cfg.CertFile}, {"--key-file", cfg.KeyFile}, {"--ca-cert", cfg.CACertFile}, {"--ca-key", cfg.CAKeyFile}} {
		if pair[1] != "" {
			args = append(args, pair[0], pair[1])
		}
	}
	return args
}

func runServerConfigRuntime(action string, args []string) error {
	fs := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	path := fs.String("config", defaultServerConfigPath(), "server config data file")
	passwordPath := fs.String("password-file", "", "password file; defaults alongside config")
	field := fs.String("field", "", "fixed installer field: listen, cert-dir, password")
	sub := fs.String("subscription-config", "", "private subscription config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected config runtime arguments")
	}
	cfg, err := loadServerRuntimeConfig(*path, *passwordPath)
	if err != nil {
		return err
	}
	if action == "read-field" {
		var value string
		switch *field {
		case "listen":
			value = cfg.Listen
		case "cert-dir":
			value = cfg.CertDir
		case "password":
			value = cfg.Password
		default:
			return errors.New("unknown installer field")
		}
		if hasControlChars(value) {
			return errors.New("installer field contains control characters")
		}
		fmt.Print(value)
		return nil
	}
	// Keep password entirely in-process; it never enters exec argv or shell.
	runtimeArgs := serverConfigRuntimeArgs(cfg)
	if *sub != "" {
		runtimeArgs = append(runtimeArgs, "--subscription-config", *sub)
	}
	// Match config edit/check-active's certificate location for custom configs.
	if os.Getenv("ANYTLS_AUTO_CERT_DIR") == "" {
		if err := os.Setenv("ANYTLS_AUTO_CERT_DIR", defaultServerAutoCertDirForConfig(*path)); err != nil {
			return err
		}
	}
	runServer(runtimeArgs)
	return nil
}
