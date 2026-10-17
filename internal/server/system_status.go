package server

// F7（evolution_log.md 第 4 轮 §5）：GET /api/v1/admin/system/status。
// 返回服务端进程与主机的运行状态。CPU 百分比由后台 goroutine 每 5s 采样并缓存，
// 请求路径只读缓存，不阻塞。

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"cyber_monitor/internal/server/history"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	gopsutilLoad "github.com/shirou/gopsutil/v4/load"
	gopsutilMem "github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
)

// systemStatusSampleInterval 是 CPU 百分比的后台采样周期（F7 定稿 5s）。
const systemStatusSampleInterval = 5 * time.Second

// SystemStatus 是 GET /api/v1/admin/system/status 的响应（字段与文档 JSON 一致）。
type SystemStatus struct {
	Version    string                `json:"version"`
	Commit     string                `json:"commit"`
	GoVersion  string                `json:"go_version"`
	StartedAt  int64                 `json:"started_at"`
	UptimeSec  int64                 `json:"uptime_sec"`
	Goroutines int                   `json:"goroutines"`
	Mem        SystemStatusMem       `json:"mem"`
	Process    SystemStatusProcess   `json:"process"`
	Host       SystemStatusHost      `json:"host"`
	WSClients  SystemStatusWSClients `json:"ws_clients"`
	DataDir    SystemStatusDataDir   `json:"data_dir"`
	// A-10：当前告警聚合（首页第二张 KPI 卡「告警中」）。
	Alerts SystemStatusAlerts `json:"alerts"`
}

// SystemStatusAlerts（A-10）：firing = 处于 FIRING 的 (阈值类规则, 节点) 数 +
// 当前离线告警中的节点数；nodes = 上述涉及的去重节点数。
type SystemStatusAlerts struct {
	Firing int `json:"firing"`
	Nodes  int `json:"nodes"`
}

type SystemStatusMem struct {
	Alloc     uint64 `json:"alloc"`
	Sys       uint64 `json:"sys"`
	HeapInuse uint64 `json:"heap_inuse"`
}

type SystemStatusProcess struct {
	CPUPercent float64 `json:"cpu_percent"`
	RSS        uint64  `json:"rss"`
}

type SystemStatusHost struct {
	Load1          float64 `json:"load1"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemUsedPercent float64 `json:"mem_used_percent"`
}

type SystemStatusWSClients struct {
	Admin  int `json:"admin"`
	Public int `json:"public"`
}

type SystemStatusDataDir struct {
	StateBytes int64 `json:"state_bytes"`
	TSDBBytes  int64 `json:"tsdb_bytes"`
	FreeBytes  int64 `json:"free_bytes"`
}

// systemStatusMonitor 周期采样进程与主机 CPU 百分比并缓存。gopsutil 的
// Percent(0) 计算的是「自上次调用以来」的增量，只有放在固定 goroutine 里周期
// 调用才有意义；请求侧直接读缓存值（采样失败时保持上次的值，初始为 0）。
type systemStatusMonitor struct {
	processCPUPercent float64AsAtomic
	hostCPUPercent    float64AsAtomic
}

func newSystemStatusMonitor() *systemStatusMonitor {
	m := &systemStatusMonitor{}
	m.processCPUPercent.Store(0)
	m.hostCPUPercent.Store(0)
	return m
}

// start 启动采样循环（随 ctx 结束退出），并立即做一次首采样作为初始缓存。
func (m *systemStatusMonitor) start(ctx context.Context) {
	if m == nil {
		return
	}
	m.sample()
	go func() {
		ticker := time.NewTicker(systemStatusSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.sample()
			}
		}
	}()
}

func (m *systemStatusMonitor) sample() {
	if proc, err := process.NewProcess(int32(os.Getpid())); err == nil {
		if percent, err := proc.Percent(0); err == nil && percent >= 0 {
			m.processCPUPercent.Store(percent)
		}
	}
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 && percents[0] >= 0 {
		m.hostCPUPercent.Store(percents[0])
	}
}

// float64AsAtomic 是 float64 的原子包装：统一以 float64 动态类型写入
// atomic.Value，避免读取侧类型断言失败。
type float64AsAtomic struct {
	value atomic.Value
}

func (f *float64AsAtomic) Store(v float64) {
	f.value.Store(v)
}

func (f *float64AsAtomic) Load() float64 {
	loaded, ok := f.value.Load().(float64)
	if !ok {
		return 0
	}
	return loaded
}

func handleAdminSystemStatus(store *Store, hub *Hub, monitor *systemStatusMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, buildSystemStatus(store, hub, monitor, time.Now()))
	}
}

func buildSystemStatus(store *Store, hub *Hub, monitor *systemStatusMonitor, now time.Time) SystemStatus {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := SystemStatus{
		GoVersion:  runtime.Version(),
		Goroutines: runtime.NumGoroutine(),
		Mem: SystemStatusMem{
			Alloc:     memStats.Alloc,
			Sys:       memStats.Sys,
			HeapInuse: memStats.HeapInuse,
		},
	}
	if store != nil {
		status.Version = store.BuildVersion()
		status.Commit = store.BuildCommit()
		startedAt := store.StartedAt()
		if !startedAt.IsZero() {
			status.StartedAt = startedAt.Unix()
			if uptime := now.Sub(startedAt).Seconds(); uptime > 0 {
				status.UptimeSec = int64(uptime)
			}
		}
	}
	if monitor != nil {
		status.Process.CPUPercent = monitor.processCPUPercent.Load()
		status.Host.CPUPercent = monitor.hostCPUPercent.Load()
	}
	if proc, err := process.NewProcess(int32(os.Getpid())); err == nil {
		if info, err := proc.MemoryInfo(); err == nil && info != nil {
			status.Process.RSS = info.RSS
		}
	}
	if loadAvg, err := gopsutilLoad.Avg(); err == nil && loadAvg != nil && loadAvg.Load1 >= 0 {
		status.Host.Load1 = loadAvg.Load1
	}
	if virtualMem, err := gopsutilMem.VirtualMemory(); err == nil && virtualMem != nil && virtualMem.UsedPercent >= 0 {
		status.Host.MemUsedPercent = virtualMem.UsedPercent
	}
	if hub != nil {
		adminCount, publicCount := hub.ClientCounts()
		status.WSClients = SystemStatusWSClients{Admin: adminCount, Public: publicCount}
	}
	if store != nil {
		status.Alerts = store.alertStatusCounts()
	}
	status.DataDir = systemStatusDataDir(store)
	return status
}

// alertStatusCounts（A-10，只读、持读锁）计算当前告警聚合：
//   - firing = 处于 FIRING 的 (阈值类规则, 节点) 数 + 当前离线告警中的节点数
//     （s.alerted 中处于告警状态的条目；恢复通知补发挂起的不计）；
//   - nodes = 上述涉及的去重节点数。
//
// 「阈值类规则」= metric 非 offline / expiry / traffic_quota 的规则（offline 由
// s.alerted 驱动、从不写入 alertStates；expiry / traffic_quota 为提醒性质，不计入）。
// 规则表中已不存在的规则 ID 同样不计。
func (s *Store) alertStatusCounts() SystemStatusAlerts {
	if s == nil {
		return SystemStatusAlerts{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	thresholdRules := make(map[string]struct{}, len(s.settings.AlertRules))
	for _, rule := range s.settings.AlertRules {
		if rule.Metric == alertMetricOffline || rule.Metric == alertMetricExpiry || rule.Metric == alertMetricTrafficQuota {
			continue
		}
		thresholdRules[rule.ID] = struct{}{}
	}

	var counts SystemStatusAlerts
	nodes := make(map[string]struct{})
	for key, state := range s.alertStates {
		if state.State != ruleStateFiring {
			continue
		}
		nodeID, ruleID, ok := parseRuleStateKey(key)
		if !ok {
			continue
		}
		if _, isThreshold := thresholdRules[ruleID]; !isThreshold {
			continue
		}
		counts.Firing++
		nodes[nodeID] = struct{}{}
	}
	for nodeID, state := range s.alerted {
		if state.RecoveryPending {
			continue
		}
		counts.Firing++
		nodes[nodeID] = struct{}{}
	}
	counts.Nodes = len(nodes)
	return counts
}

// systemStatusDataDir 统计数据目录占用：state.json 单文件大小、history 目录
// （network + offline 两个 TSDB）总大小、以及所在文件系统的剩余空间。任一统计
// 失败（如测试中的裸 Store 没有数据目录）保持 0。
func systemStatusDataDir(store *Store) SystemStatusDataDir {
	var result SystemStatusDataDir
	if store == nil {
		return result
	}
	statePath := store.StateFilePath()
	if statePath == "" {
		return result
	}
	if info, err := os.Stat(statePath); err == nil && !info.IsDir() {
		result.StateBytes = info.Size()
	}
	result.TSDBBytes = dirSizeBytes(history.HistoryRootDir(filepath.Dir(statePath)))
	if usage, err := disk.Usage(filepath.Dir(statePath)); err == nil && usage != nil && usage.Free >= 0 {
		result.FreeBytes = int64(usage.Free)
	}
	return result
}

// dirSizeBytes 递归统计目录内普通文件的总大小；单项失败（并发清理等）跳过。
func dirSizeBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		if info, err := entry.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
