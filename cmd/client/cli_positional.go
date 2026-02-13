package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"anytls/util"

	"github.com/sirupsen/logrus"
)

type positionalCLIOptions struct {
	configPath      string
	controlAddr     string
	controlExplicit bool
	cmd             string
	nodeName        string
	nodeURI         string
	backupName      string
}

func runPositionalMode(ctx context.Context, args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if strings.HasPrefix(args[0], "-") {
		return false, nil
	}

	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "cli":
		logrus.Infoln("[Client]", util.BuildInfo())
		return true, runPositionalCLI(args[1:])
	case "api":
		logrus.Infoln("[Client]", util.BuildInfo())
		return true, runPositionalAPI(ctx, args[1:])
	default:
		return false, nil
	}
}

func runPositionalAPI(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("anytls-client api", flag.ContinueOnError)
	configPath := fs.String("config", "", "Client config file path (JSON)")
	controlAddr := fs.String("control", "", "Control address")
	nodeName := fs.String("node", "", "Node name for startup override")
	listen := fs.String("l", "127.0.0.1:1080", "socks5 listen port")
	minIdle := fs.Int("m", 5, "Reserved min idle session")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfgPath := strings.TrimSpace(*configPath)
	if cfgPath == "" {
		path, err := defaultClientConfigPath()
		if err != nil {
			return fmt.Errorf("cannot determine default config path, please pass --config: %w", err)
		}
		cfgPath = path
	}
	runWithAPI(ctx, cfgPath, *listen, *minIdle, *controlAddr, *nodeName)
	return nil
}

func runPositionalCLI(args []string) error {
	opts, err := parsePositionalCLIOptions(args)
	if err != nil {
		return err
	}

	controlAddr := strings.TrimSpace(opts.controlAddr)
	effectiveConfigPath := strings.TrimSpace(opts.configPath)
	if !opts.controlExplicit {
		configPath, err := resolveShortcutConfigPath(opts.configPath)
		if err != nil {
			return err
		}
		effectiveConfigPath = configPath
		controlAddr, err = loadControlAddrFromConfig(configPath)
		if err != nil {
			return err
		}
	}
	return runCLI(effectiveConfigPath, controlAddr, opts.cmd, opts.nodeName, opts.nodeURI, opts.backupName, clientNodeConfig{})
}

func parsePositionalCLIOptions(args []string) (positionalCLIOptions, error) {
	opts := positionalCLIOptions{
		controlAddr: defaultControlAddr,
	}
	positional := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "-config":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--config requires a value")
			}
			opts.configPath = strings.TrimSpace(args[i+1])
			i++
		case "--control", "-control":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--control requires a value")
			}
			opts.controlAddr = strings.TrimSpace(args[i+1])
			opts.controlExplicit = true
			i++
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) == 0 {
		return opts, fmt.Errorf("missing cli command, usage: anytls-client cli add <URI> [NODE] [--control host:port] [--config path]")
	}

	cmd := strings.ToLower(strings.TrimSpace(positional[0]))
	positional = positional[1:]
	switch cmd {
	case "add", "import":
		if len(positional) == 0 {
			return opts, fmt.Errorf("%s requires URI, usage: anytls-client cli add <URI> [NODE]", cmd)
		}
		opts.cmd = "import"
		opts.nodeURI = strings.TrimSpace(positional[0])
		positional = positional[1:]
		if len(positional) > 0 {
			opts.nodeName = strings.TrimSpace(positional[0])
			positional = positional[1:]
		}
	case "switch", "use":
		if len(positional) == 0 {
			return opts, fmt.Errorf("%s requires NODE, usage: anytls-client cli switch <NODE>", cmd)
		}
		opts.cmd = "switch"
		opts.nodeName = strings.TrimSpace(positional[0])
		positional = positional[1:]
	case "list", "nodes":
		opts.cmd = "list"
	case "status":
		opts.cmd = "status"
	case "current":
		opts.cmd = "current"
	case "diagnose":
		opts.cmd = "diagnose"
	case "backups", "backup-list":
		opts.cmd = "backups"
	case "rollback":
		opts.cmd = "rollback"
		if len(positional) > 0 {
			opts.backupName = strings.TrimSpace(positional[0])
			positional = positional[1:]
		}
	case "stop", "shutdown", "quit":
		opts.cmd = "stop"
	case "delete", "del", "rm":
		if len(positional) == 0 {
			return opts, fmt.Errorf("%s requires NODE, usage: anytls-client cli delete <NODE>", cmd)
		}
		opts.cmd = "delete"
		opts.nodeName = strings.TrimSpace(positional[0])
		positional = positional[1:]
	default:
		return opts, fmt.Errorf("unsupported cli command: %s", cmd)
	}

	if len(positional) > 0 {
		return opts, fmt.Errorf("unexpected extra arguments: %s", strings.Join(positional, " "))
	}

	return opts, nil
}

func resolveShortcutConfigPath(configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath != "" {
		return configPath, nil
	}
	path, err := defaultClientConfigPath()
	if err != nil {
		return "", fmt.Errorf("cannot determine default config path, please pass --config: %w", err)
	}
	return path, nil
}

func loadControlAddrFromConfig(configPath string) (string, error) {
	cfg, err := loadClientConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("load config failed (%s): %w", configPath, err)
	}
	control := strings.TrimSpace(cfg.Control)
	if control == "" {
		control = defaultControlAddr
	}
	return control, nil
}
