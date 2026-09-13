//go:build !windows

package updater

import (
	"os"
	"strings"
	"syscall"
)

// CM_VERSION/CM_COMMIT 是旧进程的版本注入：exec 继承会让新二进制继续上报
// 旧版本，HasVersionUpdate 恒真并陷入无限下载-重启循环（docker 路径的
// sanitizeReplacementEnv 已做同样剔除）。
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
