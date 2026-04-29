//go:build !windows

package updater

import (
	"os"
	"syscall"
)

func RestartSelf() error {
	exePath, err := resolveExecutablePath()
	if err != nil {
		return err
	}
	args := append([]string{exePath}, os.Args[1:]...)
	return syscall.Exec(exePath, args, os.Environ())
}
