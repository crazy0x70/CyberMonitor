//go:build windows

package metrics

import "github.com/shirou/gopsutil/v4/disk"

// statFilesystemUsage is a package variable so tests can stub the
// platform-specific stat call with synthetic inputs.
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
