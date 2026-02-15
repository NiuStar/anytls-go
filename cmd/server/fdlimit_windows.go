//go:build windows

package main

func raiseServerNoFileLimit() {}

func serverCurrentNoFileLimit() uint64 { return 0 }

func serverCurrentOpenFDCount() int { return -1 }
