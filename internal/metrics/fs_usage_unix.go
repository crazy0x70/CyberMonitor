//go:build !windows

package metrics

import "syscall"

func statFilesystemUsage(path string) (filesystemUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return filesystemUsage{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	used := (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	return filesystemUsage{
		Total:       total,
		Used:        used,
		Free:        free,
		UsedPercent: percentOf(used, total),
	}, nil
}
