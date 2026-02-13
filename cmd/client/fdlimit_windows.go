//go:build windows

package main

func raiseClientNoFileLimit() {}

func currentNoFileLimit() uint64 { return 0 }
