//go:build unix

package server

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// tryLockFile 对 path 建立进程级独占文件锁，锁随返回句柄的生命周期存在，
// 关闭句柄即释放。锁被其他进程持有时返回 ErrDataDirLocked。
func tryLockFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrDataDirLocked
		}
		return nil, err
	}
	return file, nil
}
