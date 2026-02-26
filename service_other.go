//go:build !windows

package main

import (
	"fmt"
	"os"
)

func handleWindowsService(cmd string) {
	fmt.Println("Windows service commands are only supported on Windows.")
	fmt.Println("On Linux/macOS, use --print-systemd to generate a systemd unit file.")
	os.Exit(1)
}
