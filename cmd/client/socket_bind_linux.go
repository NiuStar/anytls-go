//go:build linux

package main

import "golang.org/x/sys/unix"

func setSocketBindToDevice(fd uintptr, dev string) error {
	// Linux SO_BINDTODEVICE
	const soBindToDevice = 25
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, soBindToDevice, dev)
}
