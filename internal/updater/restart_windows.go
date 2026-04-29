//go:build windows

package updater

import "fmt"

func RestartSelf() error {
	return fmt.Errorf("Windows 暂不支持自重启更新")
}
