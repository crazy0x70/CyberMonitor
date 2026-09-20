//go:build !windows

package updater

import (
	"os"
	"strings"
	"syscall"
)

func restartEnviron() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if key, _, ok := strings.Cut(entry, "="); ok && (key == containerVersionEnvKey || key == containerCommitEnvKey) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func RestartSelf() error {
	exePath, err := resolveExecutablePath()
	if err != nil {
		return err
	}
	args := append([]string{exePath}, os.Args[1:]...)
	return syscall.Exec(exePath, args, restartEnviron())
}
