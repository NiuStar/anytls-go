package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func selectNodeWithArrows(nodes []clientNodeConfig, defaultName string) (string, error) {
	if len(nodes) == 0 {
		return "", fmt.Errorf("no nodes")
	}
	if len(nodes) == 1 {
		return nodes[0].Name, nil
	}

	defaultIndex := 0
	for i, node := range nodes {
		if node.Name == defaultName {
			defaultIndex = i
			break
		}
	}

	if !isInteractiveTerminal() {
		return nodes[defaultIndex].Name, nil
	}
	if runtime.GOOS == "windows" {
		return selectNodeByNumber(nodes, defaultIndex)
	}

	sttyState, err := setupRawMode()
	if err != nil {
		return selectNodeByNumber(nodes, defaultIndex)
	}
	defer restoreTerminal(sttyState)

	_, _ = fmt.Fprint(os.Stdout, "\x1b[?25l")
	defer fmt.Fprint(os.Stdout, "\x1b[?25h")

	index := defaultIndex
	for {
		renderNodeMenu(nodes, defaultName, index)

		key, err := readSingleKey()
		if err != nil {
			return nodes[defaultIndex].Name, nil
		}
		switch key {
		case "up":
			if index > 0 {
				index--
			}
		case "down":
			if index < len(nodes)-1 {
				index++
			}
		case "enter":
			_, _ = fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H")
			return nodes[index].Name, nil
		}
	}
}

func isInteractiveTerminal() bool {
	in, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	out, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (in.Mode()&os.ModeCharDevice) != 0 && (out.Mode()&os.ModeCharDevice) != 0
}

func setupRawMode() (string, error) {
	state, err := exec.Command("stty", "-g").Output()
	if err != nil {
		return "", err
	}
	sttyState := strings.TrimSpace(string(state))
	if err := exec.Command("stty", "raw", "-echo").Run(); err != nil {
		return "", err
	}
	return sttyState, nil
}

func restoreTerminal(state string) {
	if state == "" {
		return
	}
	_ = exec.Command("stty", state).Run()
}

func selectNodeByNumber(nodes []clientNodeConfig, defaultIndex int) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("请选择节点（输入序号并回车）:")
		for i, node := range nodes {
			defMark := ""
			if i == defaultIndex {
				defMark = " (default)"
			}
			fmt.Printf("  %d) %s%s\n", i+1, node.Name, defMark)
		}
		fmt.Printf("输入序号 [默认 %d]: ", defaultIndex+1)

		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return nodes[defaultIndex].Name, nil
		}

		index := -1
		_, err = fmt.Sscanf(line, "%d", &index)
		if err != nil || index < 1 || index > len(nodes) {
			fmt.Println("无效序号，请重试。")
			continue
		}
		return nodes[index-1].Name, nil
	}
}

func renderNodeMenu(nodes []clientNodeConfig, defaultName string, index int) {
	_, _ = fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H")
	_, _ = fmt.Fprintln(os.Stdout, "请选择节点（↑/↓ 选择，Enter 确认）")
	_, _ = fmt.Fprintln(os.Stdout)
	for i, node := range nodes {
		prefix := "  "
		if i == index {
			prefix = "> "
		}
		defMark := ""
		if node.Name == defaultName {
			defMark = " (default)"
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s%s%s\n", prefix, node.Name, defMark)
	}
}

func readSingleKey() (string, error) {
	buf := make([]byte, 3)
	n, err := os.Stdin.Read(buf[:1])
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}

	switch buf[0] {
	case 13, 10:
		return "enter", nil
	case 'k', 'K':
		return "up", nil
	case 'j', 'J':
		return "down", nil
	case 27:
		_, err = os.Stdin.Read(buf[1:2])
		if err != nil {
			return "", err
		}
		if buf[1] != '[' {
			return "", nil
		}
		_, err = os.Stdin.Read(buf[2:3])
		if err != nil {
			return "", err
		}
		switch buf[2] {
		case 'A':
			return "up", nil
		case 'B':
			return "down", nil
		}
	}
	return "", nil
}
