package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func startControlServer(ctx context.Context, addr string, manager *runtimeClientManager, onSwitch func(string) error) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go handleControlConnection(c, manager, onSwitch)
		}
	}()
	return nil
}

func handleControlConnection(conn net.Conn, manager *runtimeClientManager, onSwitch func(string) error) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		_, _ = fmt.Fprintln(conn, "ERR read command:", err)
		return
	}
	cmd := strings.TrimSpace(line)
	if cmd == "" {
		_, _ = fmt.Fprintln(conn, "ERR empty command")
		return
	}

	switch {
	case cmd == "list":
		current := manager.CurrentNodeName()
		for _, name := range manager.ListNodes() {
			prefix := "  "
			if name == current {
				prefix = "* "
			}
			_, _ = fmt.Fprintf(conn, "%s%s\n", prefix, name)
		}
		_, _ = fmt.Fprintln(conn, "OK")
	case cmd == "current":
		_, _ = fmt.Fprintln(conn, manager.CurrentNodeName())
		_, _ = fmt.Fprintln(conn, "OK")
	case strings.HasPrefix(cmd, "switch "):
		target := strings.TrimSpace(strings.TrimPrefix(cmd, "switch "))
		if target == "" {
			_, _ = fmt.Fprintln(conn, "ERR missing node name")
			return
		}
		if err := manager.Switch(target); err != nil {
			_, _ = fmt.Fprintln(conn, "ERR", err)
			return
		}
		if onSwitch != nil {
			if err := onSwitch(target); err != nil {
				_, _ = fmt.Fprintln(conn, "ERR switch succeeded but save config failed:", err)
				return
			}
		}
		_, _ = fmt.Fprintf(conn, "switched to %s\n", target)
		_, _ = fmt.Fprintln(conn, "OK")
	default:
		_, _ = fmt.Fprintln(conn, "ERR unknown command, use: list | current | switch <node>")
	}
}

func runControlCommand(addr, cmd, node string) error {
	command := strings.TrimSpace(cmd)
	switch command {
	case "list", "current":
	case "switch":
		node = strings.TrimSpace(node)
		if node == "" {
			return fmt.Errorf("switch command requires -node")
		}
		command = "switch " + node
	default:
		return fmt.Errorf("unsupported -cmd: %s", command)
	}

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(conn, command); err != nil {
		return err
	}

	replyBytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	reply := string(replyBytes)
	fmt.Print(reply)
	if strings.Contains(reply, "\nERR") || strings.HasPrefix(reply, "ERR") {
		return fmt.Errorf("command failed")
	}
	return nil
}
