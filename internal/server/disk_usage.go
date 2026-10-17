package server

import "cyber_monitor/internal/metrics"

// nodeDiskUsage 返回节点的磁盘总用量（D-02：Σused / Σtotal，统计范围为 Agent
// 过滤并去重后的真实分区，即「服务器总硬盘」口径）。total == 0 时 ok=false。
func nodeDiskUsage(disks []metrics.DiskPartition) (used, total uint64, pct float64, ok bool) {
	for _, disk := range disks {
		used += disk.Used
		total += disk.Total
	}
	if total == 0 {
		return 0, 0, 0, false
	}
	return used, total, float64(used) / float64(total) * 100, true
}
