//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func setSocketBindToDevice(_ uintptr, _ string) error {
	return fmt.Errorf("SO_BINDTODEVICE is not supported on %s", runtime.GOOS)
}
