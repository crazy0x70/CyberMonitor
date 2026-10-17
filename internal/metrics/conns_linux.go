package metrics

import (
	"bytes"
	"os"
	"path/filepath"
)

// readConnectionCounts 直接统计 /proc/net/{tcp,tcp6,udp,udp6} 的条目数。
// gopsutil 的 net.Connections 为了给每条连接找到所属进程，会遍历所有进程的
// /proc/<pid>/fd，连接越多、进程越多越慢；这里只需要数量，读四个文件即可。
// 计数口径与 gopsutil 一致：同一文件内 (本地地址, 远端地址, 状态) 相同的条目只算一次。
func readConnectionCounts() (int, int) {
	root := os.Getenv("HOST_PROC")
	if root == "" {
		root = "/proc"
	}
	count := func(names ...string) int {
		total := 0
		for _, name := range names {
			data, err := os.ReadFile(filepath.Join(root, "net", name))
			if err != nil {
				continue
			}
			seen := make(map[string]struct{})
			lines := bytes.Split(data, []byte("\n"))
			for _, line := range lines[1:] {
				fields := bytes.Fields(line)
				if len(fields) < 10 {
					continue
				}
				key := string(fields[1]) + " " + string(fields[2]) + " " + string(fields[3])
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				total++
			}
		}
		return total
	}
	return count("tcp", "tcp6"), count("udp", "udp6")
}
