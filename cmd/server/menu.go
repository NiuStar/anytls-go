package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func runServerMenu() error {
	reader := stdinReader
	configPath := defaultServerConfigPath()

	for {
		fmt.Println("AnyTLS Server")
		fmt.Printf("配置文件: %s\n", configPath)
		fmt.Println()
		fmt.Println("请选择操作:")
		fmt.Println("  1) 启动服务")
		fmt.Println("  2) 编辑配置")
		fmt.Println("  3) 导出节点")
		fmt.Println("  4) 退出")
		fmt.Print("输入序号 [1-4]: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		choice := strings.TrimSpace(line)

		switch choice {
		case "1":
			cfg, err := loadServerEnvConfig(configPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Printf("未找到配置文件: %s\n", configPath)
					createNow, askErr := promptYesNo(reader, "是否现在创建配置？", true)
					if askErr != nil {
						return askErr
					}
					if createNow {
						if err := runServerConfigEdit([]string{"--config", configPath}); err != nil {
							fmt.Println("配置失败:", err)
						}
					}
					fmt.Println()
					continue
				}
				fmt.Println("读取配置失败:", err)
				fmt.Println()
				continue
			}
			if err := validateListen(cfg.Listen); err != nil {
				fmt.Println("配置 listen 无效:", err)
				fmt.Println()
				continue
			}
			if strings.TrimSpace(cfg.Password) == "" {
				fmt.Println("配置 password 为空，请先编辑配置")
				fmt.Println()
				continue
			}
			if err := validateCertDir(cfg.CertDir); err != nil {
				fmt.Println("配置 cert-dir 无效:", err)
				fmt.Println()
				continue
			}
			args := []string{"-l", cfg.Listen, "-p", cfg.Password}
			if cfg.CertDir != "" {
				args = append(args, "--cert-dir", cfg.CertDir)
			}
			fmt.Printf("正在启动服务: %s\n", cfg.Listen)
			runServer(args)
			return nil
		case "2":
			if err := runServerConfigEdit([]string{"--config", configPath}); err != nil {
				fmt.Println("编辑配置失败:", err)
			}
			fmt.Println()
		case "3":
			if err := runServerConfigExport([]string{"--config", configPath}); err != nil {
				fmt.Println("导出节点失败:", err)
			}
			fmt.Println()
		case "4", "q", "quit", "exit":
			return nil
		default:
			fmt.Println("请输入 1-4")
			fmt.Println()
		}
	}
}
