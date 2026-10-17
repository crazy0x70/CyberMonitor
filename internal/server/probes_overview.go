package server

// F7（evolution_log.md 第 4 轮 §5）：GET /api/v1/admin/probes/overview?range=1h|24h。
// 服务端聚合所有节点 × 探测目标的可用率、平均延迟、P95 延迟与平均丢包。
// 复用 QueryPublicNodeHistory（按节点查历史）与 summarizeAINetworkTrend（按节点×
// 目标做序列归一与摘要），并发查询用信号量限流（与 publicHistorySem 同规格）。

import (
	"context"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/server/history"
)

// probesOverviewConcurrency 是单次 overview 请求内并发查询节点历史的上限。
const probesOverviewConcurrency = 4

// ProbesOverviewResponse 是 GET /api/v1/admin/probes/overview 的响应。
type ProbesOverviewResponse struct {
	RangeKey string                `json:"range_key"`
	From     int64                 `json:"from"`
	To       int64                 `json:"to"`
	Targets  []ProbeTargetOverview `json:"targets"`
	// M-01（D-05）：按上报探测数据的 Agent 节点聚合的窗口统计；Targets 行为不变。
	Nodes []ProbeNodeOverview `json:"nodes"`
}

// ProbeTargetOverview 是单个探测目标（跨所有节点聚合）的窗口统计。
// AvailabilityPct / AvgLossPct 为 0–100 的百分数；无有效延迟样本时延迟字段省略。
type ProbeTargetOverview struct {
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	Nodes           int      `json:"nodes"`
	Samples         int      `json:"samples"`
	AvailabilityPct float64  `json:"availability_pct"`
	AvgLatencyMs    *float64 `json:"avg_latency_ms,omitempty"`
	P95LatencyMs    *float64 `json:"p95_latency_ms,omitempty"`
	AvgLossPct      *float64 `json:"avg_loss_pct,omitempty"`
}

// ProbeNodeOverview 是单个节点（跨其全部探测目标聚合）的窗口统计。
type ProbeNodeOverview struct {
	NodeID          string   `json:"node_id"`
	Targets         int      `json:"targets"`
	Samples         int      `json:"samples"`
	AvailabilityPct float64  `json:"availability_pct"`
	AvgLatencyMs    *float64 `json:"avg_latency_ms,omitempty"`
	P95LatencyMs    *float64 `json:"p95_latency_ms,omitempty"`
	AvgLossPct      *float64 `json:"avg_loss_pct,omitempty"`
}

func handleAdminProbesOverview(store *Store, sem chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		rangeKey, from, to, err := parsePublicHistoryRange(r.URL.Query().Get("range"), time.Now())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid range"})
			return
		}
		response := ProbesOverviewResponse{
			RangeKey: rangeKey,
			From:     from.Unix(),
			To:       to.Unix(),
			Targets:  []ProbeTargetOverview{},
			Nodes:    []ProbeNodeOverview{},
		}
		nodeIDs := store.AdminNodeIDs()
		if len(nodeIDs) == 0 {
			writeJSON(w, http.StatusOK, response)
			return
		}

		// 总预算含排队时间（与公开历史接口同策略）：先起截止再等 semaphore，
		// 避免「排队 + 查询」叠加超过 WriteTimeout。
		queryCtx, cancelQuery := context.WithTimeout(r.Context(), publicHistoryQueryTimeout)
		nodeHistories := make(map[string]map[string]*TestHistoryEntry, len(nodeIDs))
		failed := 0
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, nodeID := range nodeIDs {
			wg.Add(1)
			go func(nodeID string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-queryCtx.Done():
					return
				}
				tests, err := store.QueryPublicNodeHistory(queryCtx, nodeID, from, to)
				<-sem
				if err != nil {
					// 单节点失败不整体失败：记录后跳过该节点，聚合其余节点。
					mu.Lock()
					failed++
					mu.Unlock()
					log.Printf("probes overview 节点历史查询失败 node=%s: %v", nodeID, err)
					return
				}
				mu.Lock()
				nodeHistories[nodeID] = tests
				mu.Unlock()
			}(nodeID)
		}
		wg.Wait()
		// 在 cancel 之前读取 Err：cancel 本身会把 Err 置为 Canceled，先 cancel 再
		// 判断会把所有请求都误判为超时。此处只关心预算是否真的耗尽（或客户端
		// 断开），此时部分节点被跳过，聚合并不可信，如实返回 500。
		ctxErr := queryCtx.Err()
		cancelQuery()
		if ctxErr != nil || failed == len(nodeIDs) {
			// 全部节点查询失败（或预算耗尽）时如实报错，不返回会被误读为
			// 「无探测数据」的空列表。
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query probes overview failed"})
			return
		}

		response.Targets = aggregateProbeTargetOverviews(nodeHistories)
		// M-01（D-05）：按节点聚合，3a 目录过滤只作用于 nodes；targets 行为不变。
		response.Nodes = aggregateProbeNodeOverviews(nodeHistories, store.settingsTestCatalog())
		// B-07：序列键中的 Name 已被规范化为小写，展示名用当前 TestCatalog 的
		// 原始名称覆盖；目录中已删除的目标保持聚合名不变。
		applyProbeCatalogDisplayNames(response.Targets, store.settingsTestCatalog())
		writeJSON(w, http.StatusOK, response)
	}
}

// settingsTestCatalog 返回当前探测目录的切片拷贝（条目为值类型，浅拷贝即可）。
func (s *Store) settingsTestCatalog() []TestCatalogItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.settings.TestCatalog) == 0 {
		return nil
	}
	catalog := make([]TestCatalogItem, len(s.settings.TestCatalog))
	copy(catalog, s.settings.TestCatalog)
	return catalog
}

// probeCatalogKey 是探测目录的匹配键（B-07）：type + 小写 host + port。
type probeCatalogKey struct {
	Type string
	Host string
	Port int
}

// applyProbeCatalogDisplayNames 按 (type, 小写 host, port) 用目录里的原始 Name
// 覆盖聚合展示名；目录里已删除（或不再对应）的目标保持原样。纯函数，便于测试。
func applyProbeCatalogDisplayNames(targets []ProbeTargetOverview, catalog []TestCatalogItem) {
	if len(targets) == 0 || len(catalog) == 0 {
		return
	}
	index := make(map[probeCatalogKey]string, len(catalog))
	for _, item := range catalog {
		key := probeCatalogKey{
			Type: strings.ToLower(strings.TrimSpace(item.Type)),
			Host: strings.ToLower(strings.TrimSpace(item.Host)),
			Port: item.Port,
		}
		if key.Host == "" {
			continue
		}
		index[key] = strings.TrimSpace(item.Name)
	}
	for i := range targets {
		name, ok := index[probeCatalogKey{
			Type: strings.ToLower(strings.TrimSpace(targets[i].Type)),
			Host: strings.ToLower(strings.TrimSpace(targets[i].Host)),
			Port: targets[i].Port,
		}]
		if ok && name != "" {
			targets[i].Name = name
		}
	}
}

// probeTargetIdentity 是探测目标的标识（history.ParseNetworkSeriesKey 返回
// history 包的未导出类型，这里拆成值保存）。
type probeTargetIdentity struct {
	Type string
	Host string
	Port int
	Name string
}

// probeEntrySamples 是从一个 TestHistoryEntry 提取的样本统计（M-01 抽取，
// 目标聚合与节点聚合共用，保证取样口径一致）。
type probeEntrySamples struct {
	samples   int
	okSamples int
	latencies []float64
	lossSum   float64
	lossCount int
}

// collectProbeEntrySamples 从单个探测历史序列提取样本统计：先经
// normalizeHistoryEntry 对齐序列数组（与原先经 summarizeAINetworkTrend 的
// 归一化一致），Times 为空的序列返回 ok=false、由调用方跳过；随后统计样本
// 总数、有延迟值的成功样本、延迟样本与非空丢包样本（丢包均值 =
// lossSum / lossCount）。
func collectProbeEntrySamples(entry *TestHistoryEntry) (probeEntrySamples, bool) {
	normalizeHistoryEntry(entry)
	if len(entry.Times) == 0 {
		return probeEntrySamples{}, false
	}
	samples := probeEntrySamples{samples: len(entry.Times)}
	for idx := range entry.Times {
		if latency := entry.Latency[idx]; latency != nil {
			samples.okSamples++
			samples.latencies = append(samples.latencies, *latency)
		}
		if loss := entry.Loss[idx]; loss != nil {
			samples.lossSum += *loss
			samples.lossCount++
		}
	}
	return samples, true
}

// aggregateProbeTargetOverviews 把「节点 → 序列键 → 历史」聚合成按目标分组的
// 统计列表（纯函数，便于用 fixture 验证）。
func aggregateProbeTargetOverviews(nodeHistories map[string]map[string]*TestHistoryEntry) []ProbeTargetOverview {
	type targetAccumulator struct {
		identity  probeTargetIdentity
		nodes     map[string]struct{}
		samples   int
		okSamples int
		latencies []float64
		lossSum   float64
		lossCount int
	}

	targets := make(map[string]*targetAccumulator)
	for nodeID, series := range nodeHistories {
		for key, entry := range series {
			if key == "" || entry == nil {
				continue
			}
			parsed, err := history.ParseNetworkSeriesKey(key)
			if err != nil {
				log.Printf("probes overview 跳过非法序列键 %q: %v", key, err)
				continue
			}
			identity := probeTargetIdentity{
				Type: parsed.Type,
				Host: parsed.Host,
				Port: parsed.Port,
				Name: parsed.Name,
			}
			// M-01：从一个序列提取样本的代码抽成 collectProbeEntrySamples
			// （对齐数组 + 空序列跳过 + 样本统计），与节点聚合共用同一口径。
			samples, ok := collectProbeEntrySamples(entry)
			if !ok {
				continue
			}
			acc := targets[key]
			if acc == nil {
				acc = &targetAccumulator{
					identity: identity,
					nodes:    make(map[string]struct{}),
				}
				targets[key] = acc
			}
			acc.nodes[nodeID] = struct{}{}
			acc.samples += samples.samples
			acc.okSamples += samples.okSamples
			acc.latencies = append(acc.latencies, samples.latencies...)
			acc.lossSum += samples.lossSum
			acc.lossCount += samples.lossCount
		}
	}

	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	overviews := make([]ProbeTargetOverview, 0, len(keys))
	for _, key := range keys {
		acc := targets[key]
		overview := ProbeTargetOverview{
			Name:    acc.identity.Name,
			Type:    acc.identity.Type,
			Host:    acc.identity.Host,
			Port:    acc.identity.Port,
			Nodes:   len(acc.nodes),
			Samples: acc.samples,
		}
		if acc.samples > 0 {
			overview.AvailabilityPct = float64(acc.okSamples) / float64(acc.samples) * 100
		}
		if len(acc.latencies) > 0 {
			avgLatency := averageFloatValues(acc.latencies)
			overview.AvgLatencyMs = &avgLatency
			p95Latency := percentileFloatValues(acc.latencies, 0.95)
			overview.P95LatencyMs = &p95Latency
		}
		if acc.lossCount > 0 {
			avgLoss := acc.lossSum / float64(acc.lossCount)
			overview.AvgLossPct = &avgLoss
		}
		overviews = append(overviews, overview)
	}
	return overviews
}

// aggregateProbeNodeOverviews 把「节点 → 序列键 → 历史」聚合成按节点分组的
// 统计列表（M-01 / D-05，纯函数，便于用 fixture 验证）。取样口径与
// aggregateProbeTargetOverviews 完全一致，只是分组键从「目标」换成「节点」：
// Samples / 成功样本 / 延迟样本 / 丢包样本共用 collectProbeEntrySamples。
// 查询成功但没有任何（有效）序列的节点也输出一行零值；查询失败的节点由
// handler 不写入 nodeHistories，此处不感知。结果按 NodeID 升序排序。
//
// 3a（目录过滤）：只统计 probeCatalogKey（type + 小写 host + port，与
// applyProbeCatalogDisplayNames 同一匹配规则）能在当前目录中找到的序列，
// Targets 也只计这些序列——已从目录删除的历史目标不再把节点可用率拉低。
// 目录为空时所有节点 Targets = 0、Samples = 0。
func aggregateProbeNodeOverviews(
	nodeHistories map[string]map[string]*TestHistoryEntry,
	catalog []TestCatalogItem,
) []ProbeNodeOverview {
	catalogIndex := make(map[probeCatalogKey]struct{}, len(catalog))
	for _, item := range catalog {
		key := probeCatalogKey{
			Type: strings.ToLower(strings.TrimSpace(item.Type)),
			Host: strings.ToLower(strings.TrimSpace(item.Host)),
			Port: item.Port,
		}
		if key.Host == "" {
			continue
		}
		catalogIndex[key] = struct{}{}
	}

	overviews := make([]ProbeNodeOverview, 0, len(nodeHistories))
	for nodeID, series := range nodeHistories {
		acc := probeEntrySamples{}
		targets := 0
		for key, entry := range series {
			if key == "" || entry == nil {
				continue
			}
			parsed, err := history.ParseNetworkSeriesKey(key)
			if err != nil {
				// 非法键由 target 聚合对同一 nodeHistories 打同一条日志，这里静默跳过。
				continue
			}
			// 3a：只统计当前探测目录中仍存在的目标。
			if _, ok := catalogIndex[probeCatalogKey{
				Type: strings.ToLower(strings.TrimSpace(parsed.Type)),
				Host: strings.ToLower(strings.TrimSpace(parsed.Host)),
				Port: parsed.Port,
			}]; !ok {
				continue
			}
			samples, ok := collectProbeEntrySamples(entry)
			if !ok {
				continue
			}
			targets++
			acc.samples += samples.samples
			acc.okSamples += samples.okSamples
			acc.latencies = append(acc.latencies, samples.latencies...)
			acc.lossSum += samples.lossSum
			acc.lossCount += samples.lossCount
		}
		overview := ProbeNodeOverview{
			NodeID:  nodeID,
			Targets: targets,
			Samples: acc.samples,
		}
		if acc.samples > 0 {
			overview.AvailabilityPct = float64(acc.okSamples) / float64(acc.samples) * 100
		}
		if len(acc.latencies) > 0 {
			avgLatency := averageFloatValues(acc.latencies)
			overview.AvgLatencyMs = &avgLatency
			p95Latency := percentileFloatValues(acc.latencies, 0.95)
			overview.P95LatencyMs = &p95Latency
		}
		if acc.lossCount > 0 {
			avgLoss := acc.lossSum / float64(acc.lossCount)
			overview.AvgLossPct = &avgLoss
		}
		overviews = append(overviews, overview)
	}
	sort.Slice(overviews, func(i, j int) bool { return overviews[i].NodeID < overviews[j].NodeID })
	return overviews
}

func averageFloatValues(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

// percentileFloatValues 用最近邻秩（nearest-rank）法计算分位数：升序排序后取
// 第 ceil(p*n) 个值（1 起），与监控面板的常规口径一致。减去 1e-9 抵消浮点
// 乘积在整数边界上的向上误差（如 0.95*100 算出 95.000000000000004）。
func percentileFloatValues(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := int(math.Ceil(p*float64(len(sorted)) - 1e-9))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
