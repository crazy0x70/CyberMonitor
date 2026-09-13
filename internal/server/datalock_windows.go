//go:build windows

package server

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
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
	var overlapped windows.Overlapped
	err = windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrDataDirLocked
		}
		return nil, err
	}
	return file, nil
}
