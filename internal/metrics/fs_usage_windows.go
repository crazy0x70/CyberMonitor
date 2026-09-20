//go:build windows

package metrics

import "github.com/shirou/gopsutil/v4/disk"

var statFilesystemUsage = defaultStatFilesystemUsage

func defaultStatFilesystemUsage(path string) (filesystemUsage, error) {
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
