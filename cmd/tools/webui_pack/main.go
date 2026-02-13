package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	in := flag.String("in", "", "input HTML path")
	out := flag.String("out", "", "output HTML path")
	flag.Parse()

	if strings.TrimSpace(*in) == "" || strings.TrimSpace(*out) == "" {
		fmt.Fprintln(os.Stderr, "usage: webui_pack -in <input.html> -out <output.html>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input failed: %v\n", err)
		os.Exit(1)
	}

	packed := packHTML(raw)

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output dir failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, packed, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Packed Web UI: %s -> %s\n", *in, *out)
}

func packHTML(input []byte) []byte {
	input = bytes.TrimPrefix(input, []byte("\xef\xbb\xbf"))
	input = bytes.ReplaceAll(input, []byte("\r\n"), []byte("\n"))
	input = bytes.ReplaceAll(input, []byte("\r"), []byte("\n"))

	scanner := bufio.NewScanner(bytes.NewReader(input))
	lines := make([]string, 0, 1024)
	blankCount := 0
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		if strings.TrimSpace(line) == "" {
			blankCount++
			if blankCount > 1 {
				continue
			}
		} else {
			blankCount = 0
		}
		lines = append(lines, line)
	}

	result := strings.Join(lines, "\n")
	result = strings.TrimSpace(result) + "\n"
	return []byte(result)
}
