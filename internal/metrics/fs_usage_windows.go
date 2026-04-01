//go:build windows

package metrics

import "github.com/shirou/gopsutil/v3/disk"

func statFilesystemUsage(path string) (filesystemUsage, error) {
	usage, err := disk.Usage(path)
	if err != nil {
		return filesystemUsage{}, err
	}
	return filesystemUsage{
		Total:       usage.Total,
		Used:        usage.Used,
		Free:        usage.Free,
		UsedPercent: usage.UsedPercent,
		Fstype:      usage.Fstype,
	}, nil
}
