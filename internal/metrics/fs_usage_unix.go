//go:build !windows

package metrics

import "syscall"

// statFilesystemUsage is a package variable so tests can stub the
// platform-specific stat call with synthetic inputs (e.g. Windows-shaped
// mountpoints while running the tests on unix).
var statFilesystemUsage = defaultStatFilesystemUsage

func defaultStatFilesystemUsage(path string) (filesystemUsage, error) {
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
