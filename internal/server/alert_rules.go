package server

// F4（evolution_log.md 第 4 轮 §5）告警规则：模型规范化、加载迁移、评估引擎。
//
// 结构：
//   - 规则模型（AlertRule/AlertScope/RuleAlertState/TrafficCounter）定义在 persist.go；
//   - offline 规则由现有离线引擎（CollectAlertEvents + AlertedState）实现，本文件
//     只负责保证该规则存在、duration_sec 镜像 AlertOfflineSec、不可删除；
//   - 阈值类指标走样本环 + 三态（unknown/fail/pass）+ 状态机 OK→FIRING→OK；
//   - expiry（每天本地 09:00 + 启动后立即一次）与 traffic_quota（每分钟）为事件类
//     规则，分别用 SentLeadDays / LastStepPct 做提醒点去重；
//   - 同一 tick 中同一规则的多节点事件合并为一条消息（dispatchRuleBatchNotice）。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

// ===== 指标常量与元数据 =====

const (
	offlineAlertRuleID = "offline"

	alertMetricOffline      = "offline"
	alertMetricCPU          = "cpu"
	alertMetricLoad1        = "load1"
	alertMetricLoad5        = "load5"
	alertMetricLoad15       = "load15"
	alertMetricMemory       = "memory"
	alertMetricDisk         = "disk"
	alertMetricGPU          = "gpu"
	alertMetricGPUTemp      = "gpu_temp"
	alertMetricNetIn        = "net_in"
	alertMetricNetOut       = "net_out"
	alertMetricTCPConn      = "tcp_conn"
	alertMetricProcessCount = "process_count"
	alertMetricProbeLatency = "probe_latency"
	alertMetricProbeLoss    = "probe_loss"
	alertMetricExpiry       = "expiry"
	alertMetricTrafficQuota = "traffic_quota"

	ruleStateOK     = "OK"
	ruleStateFiring = "FIRING"

	alertOpGT = "gt"
	alertOpLT = "lt"

	alertRepeatOnce    = "once"
	alertRepeatBackoff = "backoff"

	alertScopeAll     = "all"
	alertScopeInclude = "include"

	defaultAlertRuleRatio   = 0.7
	defaultTrafficStartPct  = 80
	trafficQuotaStepPct     = 5
	trafficQuotaMaxStepPct  = 100
	alertSampleRetentionPad = 10 * time.Second
	// alertRepeatFirstInterval 是 backoff 重发的首个间隔（15 分钟起 ×2，上限 24h）。
	alertRepeatFirstInterval = 15 * time.Minute
	alertRepeatMaxInterval   = 24 * time.Hour

	defaultExpiryLeadDay1 = 7
	defaultExpiryLeadDay2 = 3
	defaultExpiryLeadDay3 = 1

	alertRuleIDPrefix = "r_"
)

// alertMetricMeta 描述单个指标的展示单位与归类。
type alertMetricMeta struct {
	unit        string // 消息中的单位后缀（net_in/net_out 特殊处理为 Mbps 展示）
	resource    bool   // 资源类：节点离线时保持原状态（unknown）
	threshold   bool   // 阈值类：走样本环 + 状态机；否则为事件类规则
	defaultName string // 迁移/默认规则名参考
}

var alertRuleMetricTable = map[string]alertMetricMeta{
	alertMetricCPU:          {unit: "%", resource: true, threshold: true},
	alertMetricLoad1:        {unit: "", resource: true, threshold: true},
	alertMetricLoad5:        {unit: "", resource: true, threshold: true},
	alertMetricLoad15:       {unit: "", resource: true, threshold: true},
	alertMetricMemory:       {unit: "%", resource: true, threshold: true},
	alertMetricDisk:         {unit: "%", resource: true, threshold: true},
	alertMetricGPU:          {unit: "%", resource: true, threshold: true},
	alertMetricGPUTemp:      {unit: "℃", resource: true, threshold: true},
	alertMetricNetIn:        {unit: "B/s", resource: true, threshold: true},
	alertMetricNetOut:       {unit: "B/s", resource: true, threshold: true},
	alertMetricTCPConn:      {unit: "个", resource: true, threshold: true},
	alertMetricProcessCount: {unit: "个", resource: true, threshold: true},
	alertMetricProbeLatency: {unit: "ms", resource: true, threshold: true},
	alertMetricProbeLoss:    {unit: "%", resource: true, threshold: true},
	alertMetricExpiry:       {unit: "天"},
	alertMetricTrafficQuota: {unit: "%"},
}

func isValidAlertMetric(metric string) bool {
	if metric == alertMetricOffline {
		return true
	}
	_, ok := alertRuleMetricTable[metric]
	return ok
}

// ===== 规则规范化 / 加载迁移 =====

// ensureOfflineAlertRule 是加载迁移（mergeSettings / initSettings 调用）：保证规则表
// 含且仅含一条 metric=offline 的内置规则，且 duration_sec 镜像 AlertOfflineSec。
// 旧 state.json（无 alert_rules）由此合成 {ID:"offline", Name:"节点离线", ...}。
func ensureOfflineAlertRule(settings *Settings) {
	if settings == nil {
		return
	}
	found := false
	kept := make([]AlertRule, 0, len(settings.AlertRules))
	for _, rule := range settings.AlertRules {
		if rule.Metric != alertMetricOffline {
			kept = append(kept, rule)
			continue
		}
		if found {
			continue // 重复的 offline 规则丢弃，只保留第一条
		}
		found = true
		kept = append(kept, enforceOfflineAlertRuleShape(rule, mirrorOfflineSec(settings)))
	}
	if !found {
		kept = append([]AlertRule{builtinOfflineAlertRule(mirrorOfflineSec(settings))}, kept...)
	}
	settings.AlertRules = kept
}

func mirrorOfflineSec(settings *Settings) int64 {
	if settings == nil || settings.AlertOfflineSec <= 0 {
		return defaultAlertOfflineSec
	}
	return settings.AlertOfflineSec
}

func builtinOfflineAlertRule(offlineSec int64) AlertRule {
	return AlertRule{
		ID:            offlineAlertRuleID,
		Name:          "节点离线",
		Enabled:       true,
		Metric:        alertMetricOffline,
		Op:            alertOpGT,
		Threshold:     float64(offlineSec),
		DurationSec:   offlineSec,
		Ratio:         defaultAlertRuleRatio,
		Scope:         AlertScope{Mode: alertScopeAll},
		NotifyRecover: true,
		Repeat:        alertRepeatOnce,
	}
}

// enforceOfflineAlertRuleShape 固化内置 offline 规则的可变面：只能停用或修改范围与
// 渠道；ID/Metric/名称/持续时间等一律按镜像值重写。
func enforceOfflineAlertRuleShape(rule AlertRule, offlineSec int64) AlertRule {
	base := builtinOfflineAlertRule(offlineSec)
	rule.ID = base.ID
	rule.Name = base.Name
	rule.Metric = base.Metric
	rule.Op = base.Op
	rule.Threshold = base.Threshold
	rule.DurationSec = base.DurationSec
	rule.Ratio = base.Ratio
	rule.ProbeName = ""
	rule.LeadDays = nil
	rule.NotifyRecover = true
	rule.Repeat = base.Repeat
	return rule
}

// syncOfflineAlertRuleDuration 在 AlertOfflineSec 单独变更（本次请求未携带规则列表）
// 时，把内置 offline 规则的 duration_sec 同步为新的镜像值。
func syncOfflineAlertRuleDuration(rules []AlertRule, offlineSec int64) []AlertRule {
	if offlineSec <= 0 {
		offlineSec = defaultAlertOfflineSec
	}
	for i := range rules {
		if rules[i].Metric == alertMetricOffline {
			rules[i].DurationSec = offlineSec
			rules[i].Threshold = float64(offlineSec)
		}
	}
	return rules
}

// offlineAlertRuleLocked 返回内置 offline 规则；加载迁移保证其存在。
// 找不到时返回按当前设置镜像合成的内置规则（直接构造 Store 的旧路径兜底）。
func (s *Store) offlineAlertRuleLocked() AlertRule {
	for _, rule := range s.settings.AlertRules {
		if rule.Metric == alertMetricOffline {
			return rule
		}
	}
	return builtinOfflineAlertRule(mirrorOfflineSec(&s.settings))
}

// normalizeAlertRules 规范化并校验整份规则列表（SettingsUpdate.AlertRules 用）。
// 内置 offline 规则不可删除：列表缺失时自动补回；重复时只保留第一条。
func normalizeAlertRules(rules []AlertRule, offlineSec int64) ([]AlertRule, error) {
	if len(rules) == 0 {
		return []AlertRule{builtinOfflineAlertRule(offlineSec)}, nil
	}
	normalized := make([]AlertRule, 0, len(rules)+1)
	seenIDs := make(map[string]struct{}, len(rules))
	hasOffline := false
	for _, rule := range rules {
		item, err := normalizeAlertRule(rule, offlineSec)
		if err != nil {
			return nil, err
		}
		if item.Metric == alertMetricOffline {
			if hasOffline {
				continue
			}
			hasOffline = true
		}
		if _, dup := seenIDs[item.ID]; dup {
			return nil, fmt.Errorf("告警规则 ID 重复：%s", item.ID)
		}
		seenIDs[item.ID] = struct{}{}
		normalized = append(normalized, item)
	}
	if !hasOffline {
		normalized = append([]AlertRule{builtinOfflineAlertRule(offlineSec)}, normalized...)
	}
	return normalized, nil
}

func normalizeAlertRule(rule AlertRule, offlineSec int64) (AlertRule, error) {
	if offlineSec <= 0 {
		offlineSec = defaultAlertOfflineSec
	}
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		id, err := randomToken(10)
		if err != nil {
			return AlertRule{}, err
		}
		rule.ID = alertRuleIDPrefix + id
	}
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Metric = strings.TrimSpace(rule.Metric)
	if !isValidAlertMetric(rule.Metric) {
		return AlertRule{}, fmt.Errorf("未知的告警指标：%s", rule.Metric)
	}
	if rule.Metric == alertMetricOffline {
		return enforceOfflineAlertRuleShape(rule, offlineSec), nil
	}
	rule.Op = strings.TrimSpace(rule.Op)
	if rule.Op == "" {
		rule.Op = alertOpGT
	}
	if rule.Op != alertOpGT && rule.Op != alertOpLT {
		return AlertRule{}, fmt.Errorf("告警比较符仅支持 > 或 <（%s）", rule.Op)
	}
	if rule.Threshold < 0 {
		rule.Threshold = 0
	}
	if rule.DurationSec < 0 {
		rule.DurationSec = 0
	}
	if rule.DurationSec > maxDurationSettingSec {
		rule.DurationSec = maxDurationSettingSec
	}
	if rule.Ratio <= 0 {
		rule.Ratio = defaultAlertRuleRatio
	}
	if rule.Ratio > 1 {
		rule.Ratio = 1
	}
	rule.Repeat = strings.TrimSpace(rule.Repeat)
	if rule.Repeat == "" {
		rule.Repeat = alertRepeatOnce
	}
	if rule.Repeat != alertRepeatOnce && rule.Repeat != alertRepeatBackoff {
		return AlertRule{}, fmt.Errorf("重复提醒仅支持 once 或 backoff（%s）", rule.Repeat)
	}
	scope, err := normalizeAlertScope(rule.Scope)
	if err != nil {
		return AlertRule{}, err
	}
	rule.Scope = scope
	rule.ChannelIDs = normalizeUniqueStrings(rule.ChannelIDs, nil)
	rule.ProbeName = strings.TrimSpace(rule.ProbeName)
	if (rule.Metric == alertMetricProbeLatency || rule.Metric == alertMetricProbeLoss) && rule.ProbeName == "" {
		return AlertRule{}, errors.New("探测类指标需要指定探测目标（probe_name）")
	}
	rule.LeadDays = normalizeAlertLeadDays(rule.LeadDays)
	return rule, nil
}

func normalizeAlertScope(scope AlertScope) (AlertScope, error) {
	scope.Mode = strings.TrimSpace(scope.Mode)
	if scope.Mode == "" {
		scope.Mode = alertScopeAll
	}
	if scope.Mode != alertScopeAll && scope.Mode != alertScopeInclude {
		return AlertScope{}, fmt.Errorf("规则范围仅支持 all 或 include（%s）", scope.Mode)
	}
	scope.Nodes = normalizeUniqueStrings(scope.Nodes, nil)
	scope.Groups = normalizeUniqueStrings(scope.Groups, nil)
	// D-05：exclude 在 all 与 include 两种模式下都生效，include 不再丢弃。
	scope.Exclude = normalizeUniqueStrings(scope.Exclude, nil)
	return scope, nil
}

func normalizeAlertLeadDays(days []int) []int {
	if len(days) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(days))
	normalized := make([]int, 0, len(days))
	for _, day := range days {
		if day <= 0 {
			continue
		}
		if _, dup := seen[day]; dup {
			continue
		}
		seen[day] = struct{}{}
		normalized = append(normalized, day)
	}
	if len(normalized) == 0 {
		return nil
	}
	sort.Sort(sort.Reverse(sort.IntSlice(normalized)))
	return normalized
}

func alertRuleLeadDays(rule AlertRule) []int {
	if len(rule.LeadDays) > 0 {
		return rule.LeadDays
	}
	return []int{defaultExpiryLeadDay1, defaultExpiryLeadDay2, defaultExpiryLeadDay3}
}

// cloneAlertRules 深拷贝规则列表（含 Scope 内的切片与 ChannelIDs / LeadDays）。
func cloneAlertRules(rules []AlertRule) []AlertRule {
	if rules == nil {
		return nil
	}
	cloned := make([]AlertRule, len(rules))
	for i, rule := range rules {
		rule.Scope.Nodes = slices.Clone(rule.Scope.Nodes)
		rule.Scope.Groups = slices.Clone(rule.Scope.Groups)
		rule.Scope.Exclude = slices.Clone(rule.Scope.Exclude)
		rule.ChannelIDs = slices.Clone(rule.ChannelIDs)
		rule.LeadDays = slices.Clone(rule.LeadDays)
		cloned[i] = rule
	}
	return cloned
}

// normalizeAlertStates 在加载时校验 AlertStates 的 key（nodeID|ruleID）与状态值，
// 丢弃非法条目并记录警告，单个坏 key 不阻止启动。
func normalizeAlertStates(states map[string]RuleAlertState) map[string]RuleAlertState {
	normalized := make(map[string]RuleAlertState, len(states))
	for key, state := range states {
		nodeID, ruleID, ok := parseRuleStateKey(key)
		if !ok || nodeID == "" || ruleID == "" {
			log.Printf("忽略 alert_states 中非法的键: %q", key)
			continue
		}
		if state.State != ruleStateFiring {
			state.State = ruleStateOK
		}
		normalized[ruleStateKey(nodeID, ruleID)] = state
	}
	return normalized
}

func ruleStateKey(nodeID, ruleID string) string {
	return nodeID + "|" + ruleID
}

// parseRuleStateKey 按最后一个 "|" 拆分（nodeID 允许包含 "|"，规则 ID 不允许）。
func parseRuleStateKey(key string) (string, string, bool) {
	idx := strings.LastIndex(key, "|")
	if idx <= 0 || idx == len(key)-1 {
		return "", "", false
	}
	return key[:idx], key[idx+1:], true
}

// ===== 范围匹配 / 指标取值 =====

// ruleScopeMatches 判断节点是否落在规则范围内（调用方已另行校验 AlertEnabled）。
// D-05：exclude 在 all 与 include 两种模式下都生效——命中 exclude 的节点一律不匹配。
func ruleScopeMatches(scope AlertScope, nodeID string, profile *NodeProfile) bool {
	if slices.Contains(scope.Exclude, nodeID) {
		return false
	}
	mode := strings.TrimSpace(scope.Mode)
	if mode == alertScopeInclude {
		if slices.Contains(scope.Nodes, nodeID) {
			return true
		}
		if profile == nil {
			return false
		}
		for _, selection := range scope.Groups {
			if alertGroupSelectionMatches(selection, profile) {
				return true
			}
		}
		return false
	}
	return true
}

func alertGroupSelectionMatches(selection string, profile *NodeProfile) bool {
	group, tag := parseGroupSelection(selection)
	if group == "" {
		return false
	}
	selections := normalizeGroupSelections(profile.Groups)
	if len(selections) == 0 {
		selections = selectionsFromGroupTags(profile.Group, profile.Tags)
	}
	for _, item := range selections {
		itemGroup, itemTag := parseGroupSelection(item)
		if itemGroup != group {
			continue
		}
		if tag == "" || itemTag == tag {
			return true
		}
	}
	return false
}

// alertMetricValue 从节点统计中提取指标当前值。known=false 表示指标缺失
// （无 GPU、memory.total == 0、探测目标不存在等），评估为 unknown。
func alertMetricValue(metric, probeName string, stats metrics.NodeStats) (float64, bool) {
	switch metric {
	case alertMetricCPU:
		return stats.CPU.UsagePercent, true
	case alertMetricLoad1:
		return stats.CPU.Load1, true
	case alertMetricLoad5:
		return stats.CPU.Load5, true
	case alertMetricLoad15:
		return stats.CPU.Load15, true
	case alertMetricMemory:
		if stats.Memory.Total == 0 {
			return 0, false
		}
		return stats.Memory.UsedPercent, true
	case alertMetricDisk:
		// B-06（D-02）：磁盘使用率 = Σused / Σtotal（服务器总硬盘口径）。
		_, _, pct, ok := nodeDiskUsage(stats.Disk)
		if !ok {
			return 0, false
		}
		return pct, true
	case alertMetricGPU:
		if len(stats.GPU) == 0 {
			return 0, false
		}
		maxUtilization := 0.0
		for _, gpu := range stats.GPU {
			if gpu.UtilizationPercent > maxUtilization {
				maxUtilization = gpu.UtilizationPercent
			}
		}
		return maxUtilization, true
	case alertMetricGPUTemp:
		if len(stats.GPU) == 0 {
			return 0, false
		}
		maxTemp := 0.0
		for _, gpu := range stats.GPU {
			if gpu.TemperatureC > maxTemp {
				maxTemp = gpu.TemperatureC
			}
		}
		if maxTemp <= 0 {
			return 0, false
		}
		return maxTemp, true
	case alertMetricNetIn:
		return stats.Network.RxBytesPerSec, true
	case alertMetricNetOut:
		return stats.Network.TxBytesPerSec, true
	case alertMetricTCPConn:
		return float64(stats.TCPConns), true
	case alertMetricProcessCount:
		return float64(stats.ProcessCount), true
	case alertMetricProbeLatency:
		test, ok := findNetworkTestResult(stats.NetworkTests, probeName)
		if !ok || test.LatencyMs == nil {
			return 0, false
		}
		return *test.LatencyMs, true
	case alertMetricProbeLoss:
		test, ok := findNetworkTestResult(stats.NetworkTests, probeName)
		if !ok {
			return 0, false
		}
		return test.PacketLoss, true
	}
	return 0, false
}

func findNetworkTestResult(tests []metrics.NetworkTestResult, name string) (metrics.NetworkTestResult, bool) {
	name = strings.TrimSpace(name)
	for _, test := range tests {
		if strings.TrimSpace(test.Name) == name {
			return test, true
		}
	}
	return metrics.NetworkTestResult{}, false
}

func alertValueViolated(rule AlertRule, value float64) bool {
	if rule.Op == alertOpLT {
		return value < rule.Threshold
	}
	return value > rule.Threshold
}

// ===== 样本环与窗口判定 =====

type ruleSample struct {
	at       time.Time
	violated bool
}

// appendRuleSample 追加样本并按 duration_sec + 10s 修剪。
func appendRuleSample(samples []ruleSample, at time.Time, violated bool, durationSec int64) []ruleSample {
	samples = append(samples, ruleSample{at: at, violated: violated})
	retention := time.Duration(durationSec)*time.Second + alertSampleRetentionPad
	cutoff := at.Add(-retention)
	// 保留一个早于 cutoff 的样本作为窗口 carry-in（评估时按窗口起点裁剪）。
	keep := 0
	for keep < len(samples) && samples[keep].at.Before(cutoff) {
		keep++
	}
	if keep > 0 {
		if keep < len(samples) {
			keep-- // 保留最后一个越界样本
		}
		if keep > 0 {
			samples = samples[keep:]
		}
	}
	return samples
}

// evaluateSampleWindow 判定窗口结论：窗口内越限时间 > ratio × window 即 fail。
// durationSec <= 0 表示单次采样即判定（取最新样本）。
func evaluateSampleWindow(samples []ruleSample, now time.Time, durationSec int64, ratio float64) bool {
	if len(samples) == 0 {
		return false
	}
	if durationSec <= 0 {
		return samples[len(samples)-1].violated
	}
	window := time.Duration(durationSec) * time.Second
	windowStart := now.Add(-window)
	var violatedTime time.Duration
	for i, sample := range samples {
		segmentStart := sample.at
		if segmentStart.Before(windowStart) {
			segmentStart = windowStart
		}
		segmentEnd := now
		if i+1 < len(samples) && samples[i+1].at.Before(now) {
			segmentEnd = samples[i+1].at
		}
		if segmentEnd.After(segmentStart) && sample.violated {
			violatedTime += segmentEnd.Sub(segmentStart)
		}
	}
	return violatedTime > time.Duration(float64(window)*ratio)
}

// ===== 评估引擎 =====

// RuleEvalCadence 由 tickRunner 计算：expiry 每天 09:00（+启动一次）、traffic_quota
// 每分钟；阈值类规则每个 tick 都评估。存在待重试事件时事件类规则也会被评估。
type RuleEvalCadence struct {
	ExpiryScan  bool
	TrafficScan bool
}

type ruleNoticeKind string

const (
	ruleNoticeAlert    ruleNoticeKind = "alert"
	ruleNoticeRecovery ruleNoticeKind = "recovery"
)

// RuleAlertEvent 是一个 (rule, node) 的待投递通知，Delivered 记录已送达渠道
// （只补发失败渠道，与离线引擎语义一致）。
type RuleAlertEvent struct {
	RuleID  string
	NodeID  string
	Display string
	// 消息素材
	Value       float64 // 阈值类：当前值；expiry：剩余天数；traffic：使用百分比
	UsedBytes   uint64  // traffic_quota
	QuotaBytes  uint64  // traffic_quota
	Days        int     // expiry：剩余天数
	ExpireDate  string  // expiry（本地日期）
	DurationSec int64   // 告警：规则持续窗口；恢复：实际持续时长
	Delivered   map[string]bool
}

// RuleNoticeBatch 是同一 tick 中同一规则（同一种通知类型）的合并批次。
type RuleNoticeBatch struct {
	Rule      AlertRule
	Kind      ruleNoticeKind
	SiteTitle string
	Channels  []NotifyChannel
	Events    []RuleAlertEvent
}

// CollectRuleEvents 评估所有启用的非 offline 规则并产出待投递批次。
// 调用方（runOnce）负责在锁外投递与记录回执。
func (s *Store) CollectRuleEvents(now time.Time, cadence RuleEvalCadence) []RuleNoticeBatch {
	s.mu.Lock()

	siteTitle := normalizeSiteTitle(s.settings.SiteTitle)
	channels := enabledNotifyChannels(s.settings)
	if s.alertStates == nil {
		s.alertStates = make(map[string]RuleAlertState)
	}
	if s.ruleSamples == nil {
		s.ruleSamples = make(map[string][]ruleSample)
	}

	nodeIDs := make([]string, 0, len(s.nodes))
	for nodeID := range s.nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	offlineThreshold := s.offlineAlertThreshold()

	type ruleBatchPair struct {
		rule          AlertRule
		channels      []NotifyChannel
		alertEvents   []RuleAlertEvent
		recoverEvents []RuleAlertEvent
	}
	batches := map[string]*ruleBatchPair{}
	var order []string
	addEvent := func(rule AlertRule, ruleChannels []NotifyChannel, event RuleAlertEvent, recovery bool) {
		pair, ok := batches[rule.ID]
		if !ok {
			pair = &ruleBatchPair{rule: rule, channels: ruleChannels}
			batches[rule.ID] = pair
			order = append(order, rule.ID)
		}
		if recovery {
			pair.recoverEvents = append(pair.recoverEvents, event)
		} else {
			pair.alertEvents = append(pair.alertEvents, event)
		}
	}

	needsPersist := false
	liveRuleIDs := make(map[string]struct{}, len(s.settings.AlertRules))
	for _, rule := range s.settings.AlertRules {
		if !rule.Enabled || rule.Metric == alertMetricOffline {
			continue
		}
		liveRuleIDs[rule.ID] = struct{}{}
		ruleChannels := ruleChannelsFor(rule, channels)
		meta := alertRuleMetricTable[rule.Metric]
		switch {
		case meta.threshold:
			alertEvents, recoveryEvents, changed := s.evaluateThresholdRuleLocked(rule, nodeIDs, now, offlineThreshold)
			needsPersist = needsPersist || changed
			for _, event := range alertEvents {
				addEvent(rule, ruleChannels, event, false)
			}
			for _, event := range recoveryEvents {
				addEvent(rule, ruleChannels, event, true)
			}
		case rule.Metric == alertMetricExpiry:
			if !cadence.ExpiryScan && !s.ruleRetryDueLocked(rule.ID, now) {
				continue
			}
			events, changed := s.collectExpiryEventsLocked(rule, now)
			needsPersist = needsPersist || changed
			for _, event := range events {
				addEvent(rule, ruleChannels, event, false)
			}
		case rule.Metric == alertMetricTrafficQuota:
			if !cadence.TrafficScan && !s.ruleRetryDueLocked(rule.ID, now) {
				continue
			}
			events, changed := s.collectTrafficQuotaEventsLocked(rule, now)
			needsPersist = needsPersist || changed
			for _, event := range events {
				addEvent(rule, ruleChannels, event, false)
			}
		}
	}

	// 清理：节点已删除 / 规则已删除（含停用后残留样本）。
	for key := range s.alertStates {
		nodeID, ruleID, ok := parseRuleStateKey(key)
		if !ok {
			delete(s.alertStates, key)
			delete(s.ruleSamples, key)
			needsPersist = true
			continue
		}
		if _, nodeExists := s.nodes[nodeID]; nodeExists {
			if _, ruleExists := liveRuleIDs[ruleID]; ruleExists {
				continue
			}
		}
		delete(s.alertStates, key)
		delete(s.ruleSamples, key)
		needsPersist = true
	}
	for key := range s.ruleSamples {
		nodeID, ruleID, ok := parseRuleStateKey(key)
		if !ok {
			delete(s.ruleSamples, key)
			continue
		}
		if _, nodeExists := s.nodes[nodeID]; !nodeExists {
			delete(s.ruleSamples, key)
			continue
		}
		if _, ruleExists := liveRuleIDs[ruleID]; !ruleExists {
			delete(s.ruleSamples, key)
		}
	}

	s.mu.Unlock()
	if needsPersist {
		s.persistLogged()
	}

	if len(order) == 0 {
		return nil
	}
	notices := make([]RuleNoticeBatch, 0, len(order)*2)
	for _, ruleID := range order {
		pair := batches[ruleID]
		if len(pair.alertEvents) > 0 {
			notices = append(notices, RuleNoticeBatch{
				Rule: pair.rule, Kind: ruleNoticeAlert,
				SiteTitle: siteTitle, Channels: pair.channels, Events: pair.alertEvents,
			})
		}
		if len(pair.recoverEvents) > 0 {
			notices = append(notices, RuleNoticeBatch{
				Rule: pair.rule, Kind: ruleNoticeRecovery,
				SiteTitle: siteTitle, Channels: pair.channels, Events: pair.recoverEvents,
			})
		}
	}
	return notices
}

func ruleChannelsFor(rule AlertRule, enabled []NotifyChannel) []NotifyChannel {
	if len(rule.ChannelIDs) == 0 {
		return enabled
	}
	wanted := make(map[string]struct{}, len(rule.ChannelIDs))
	for _, id := range rule.ChannelIDs {
		wanted[id] = struct{}{}
	}
	var selected []NotifyChannel
	for _, channel := range enabled {
		if _, ok := wanted[channel.ID]; ok {
			selected = append(selected, channel)
		}
	}
	return selected
}

// ruleRetryDueLocked 检查某条规则是否存在已到期的失败补发（事件类规则在非扫描
// tick 也能补发未送达的提醒）。
func (s *Store) ruleRetryDueLocked(ruleID string, now time.Time) bool {
	suffix := "|" + ruleID
	for key, state := range s.alertStates {
		if !strings.HasSuffix(key, suffix) {
			continue
		}
		if !state.NextRetryAt.IsZero() && !now.Before(state.NextRetryAt) {
			return true
		}
	}
	return false
}

// evaluateThresholdRuleLocked 评估阈值类规则：三态 + 状态机 OK→FIRING→OK。
func (s *Store) evaluateThresholdRuleLocked(rule AlertRule, nodeIDs []string, now time.Time, offlineThreshold time.Duration) (alertEvents, recoveryEvents []RuleAlertEvent, changed bool) {
	for _, nodeID := range nodeIDs {
		node := s.nodes[nodeID]
		profile := s.profiles[nodeID]
		if !isAlertEnabled(profile) {
			continue
		}
		if !ruleScopeMatches(rule.Scope, nodeID, profile) {
			continue
		}
		key := ruleStateKey(nodeID, rule.ID)
		state, hasState := s.alertStates[key]

		// 待恢复补发：OK 状态但上一轮恢复通知未送达全部渠道。
		if hasState && state.State == ruleStateOK && ruleNotifyRetryDue(state, now) {
			event := RuleAlertEvent{
				RuleID: rule.ID, NodeID: nodeID,
				Display:     resolveAlertDisplay(profile, node.Stats, nodeID),
				DurationSec: int64(now.Sub(state.FiringSince).Seconds()),
				Delivered:   cloneNotifyBoolMap(state.Delivered),
			}
			if state.FiringSince.IsZero() {
				event.DurationSec = 0
			}
			recoveryEvents = append(recoveryEvents, event)
			state.NextRetryAt = time.Time{}
			s.alertStates[key] = state
			continue
		}

		value, known := alertMetricValue(rule.Metric, rule.ProbeName, node.Stats)
		offline := now.Sub(node.LastSeen) >= offlineThreshold
		if !known || offline {
			// unknown：保持上一个状态，不触发也不恢复，不追加样本。
			continue
		}
		violated := alertValueViolated(rule, value)
		samples := appendRuleSample(s.ruleSamples[key], now, violated, rule.DurationSec)
		s.ruleSamples[key] = samples
		fail := evaluateSampleWindow(samples, now, rule.DurationSec, rule.Ratio)

		switch {
		case fail && (!hasState || state.State != ruleStateFiring):
			// OK→FIRING：发告警。
			alertEvents = append(alertEvents, RuleAlertEvent{
				RuleID: rule.ID, NodeID: nodeID,
				Display:     resolveAlertDisplay(profile, node.Stats, nodeID),
				Value:       value,
				DurationSec: rule.DurationSec,
			})
			next := RuleAlertState{
				State:          ruleStateFiring,
				FiringSince:    now,
				LastNotifiedAt: now,
			}
			if rule.Repeat == alertRepeatBackoff {
				next.NextRepeatAt = now.Add(alertRepeatFirstInterval)
			}
			s.alertStates[key] = next
			changed = true
		case fail && state.State == ruleStateFiring:
			// FIRING 维持：优先失败补发，其次按 Repeat 重发。
			if ruleNotifyRetryDue(state, now) {
				alertEvents = append(alertEvents, RuleAlertEvent{
					RuleID: rule.ID, NodeID: nodeID,
					Display:     resolveAlertDisplay(profile, node.Stats, nodeID),
					Value:       value,
					DurationSec: rule.DurationSec,
					Delivered:   cloneNotifyBoolMap(state.Delivered),
				})
				// 失败补发不算 Repeat 重发：不推进 LastNotifiedAt，保证倍增基数
				// step = NextRepeatAt - LastNotifiedAt 不被补发压缩（文档：15min
				// 起 ×2，上限 24h；补发紧邻 NextRepeatAt 到期时尤甚）。
				state.NextRetryAt = time.Time{}
				s.alertStates[key] = state
			} else if !state.NextRepeatAt.IsZero() && !now.Before(state.NextRepeatAt) {
				alertEvents = append(alertEvents, RuleAlertEvent{
					RuleID: rule.ID, NodeID: nodeID,
					Display:     resolveAlertDisplay(profile, node.Stats, nodeID),
					Value:       value,
					DurationSec: rule.DurationSec,
				})
				step := state.NextRepeatAt.Sub(state.LastNotifiedAt)
				if step <= 0 {
					step = alertRepeatFirstInterval
				}
				interval := step * 2
				if interval > alertRepeatMaxInterval {
					interval = alertRepeatMaxInterval
				}
				state.Delivered = nil
				state.RetryCount = 0
				state.NextRetryAt = time.Time{}
				state.LastNotifiedAt = now
				state.NextRepeatAt = now.Add(interval)
				s.alertStates[key] = state
			}
		case !fail && hasState && state.State == ruleStateFiring:
			// FIRING→OK：按 NotifyRecover 发恢复。
			duration := int64(now.Sub(state.FiringSince).Seconds())
			if state.FiringSince.IsZero() {
				duration = 0
			}
			// B-05：恢复事件的 Delivered 不携带告警阶段的送达记录——否则已送达过
			// 告警的渠道会被认为无需恢复通知。
			event := RuleAlertEvent{
				RuleID: rule.ID, NodeID: nodeID,
				Display:     resolveAlertDisplay(profile, node.Stats, nodeID),
				Value:       value,
				DurationSec: duration,
			}
			if rule.NotifyRecover {
				recoveryEvents = append(recoveryEvents, event)
				state.State = ruleStateOK
				state.NextRetryAt = time.Time{}
				state.NextRepeatAt = time.Time{}
				state.Delivered = nil
				state.RetryCount = 0
				s.alertStates[key] = state
			} else {
				delete(s.alertStates, key)
			}
			delete(s.ruleSamples, key)
			changed = true
		}
	}
	return alertEvents, recoveryEvents, changed
}

func ruleNotifyRetryDue(state RuleAlertState, now time.Time) bool {
	return !state.NextRetryAt.IsZero() && !now.Before(state.NextRetryAt)
}

// collectExpiryEventsLocked 评估到期提醒：命中 lead_days 中任一天时提醒一次，
// 以 (node, ExpireAt, leadDay) 去重（SentLeadDays；到期时间后移导致 daysLeft
// 回升时整体清零重置）。
func (s *Store) collectExpiryEventsLocked(rule AlertRule, now time.Time) ([]RuleAlertEvent, bool) {
	var events []RuleAlertEvent
	changed := false
	leadDays := alertRuleLeadDays(rule)
	for nodeID := range s.nodes {
		profile := s.profiles[nodeID]
		if profile == nil {
			continue
		}
		key := ruleStateKey(nodeID, rule.ID)
		// B-04：与阈值类规则一致，尊重节点总开关与规则范围。
		if !isAlertEnabled(profile) || !ruleScopeMatches(rule.Scope, nodeID, profile) {
			if _, has := s.alertStates[key]; has {
				delete(s.alertStates, key)
				changed = true
			}
			continue
		}
		node := s.nodes[nodeID]
		state, hasState := s.alertStates[key]
		if profile.ExpireAt <= 0 || profile.AutoRenew {
			if hasState {
				delete(s.alertStates, key)
				changed = true
			}
			continue
		}
		daysLeft := alertCalendarDaysUntil(now, profile.ExpireAt)
		if daysLeft < 0 {
			if hasState {
				delete(s.alertStates, key)
				changed = true
			}
			continue
		}
		if len(state.SentLeadDays) > 0 {
			minSent := state.SentLeadDays[0]
			for _, day := range state.SentLeadDays {
				if day < minSent {
					minSent = day
				}
			}
			if daysLeft > minSent {
				// 到期时间被后移：重置提醒点。
				state.SentLeadDays = nil
			}
		}
		hit := 0
		for _, day := range leadDays {
			if day == daysLeft {
				hit = day
				break
			}
		}
		expireDate := time.Unix(profile.ExpireAt, 0).Local().Format("2006-01-02")
		display := resolveAlertDisplay(profile, node.Stats, nodeID)
		if hit > 0 {
			if !slices.Contains(state.SentLeadDays, hit) {
				events = append(events, RuleAlertEvent{
					RuleID: rule.ID, NodeID: nodeID, Display: display,
					Value: float64(daysLeft), Days: daysLeft, ExpireDate: expireDate,
				})
				state.SentLeadDays = append(state.SentLeadDays, hit)
				state.State = ruleStateFiring
				if state.FiringSince.IsZero() {
					state.FiringSince = now
				}
				state.LastNotifiedAt = now
				s.alertStates[key] = state
				changed = true
			} else if ruleNotifyRetryDue(state, now) {
				// 已提醒但未送达全部渠道：补发。
				events = append(events, RuleAlertEvent{
					RuleID: rule.ID, NodeID: nodeID, Display: display,
					Value: float64(daysLeft), Days: daysLeft, ExpireDate: expireDate,
					Delivered: cloneNotifyBoolMap(state.Delivered),
				})
				state.NextRetryAt = time.Time{}
				state.LastNotifiedAt = now
				s.alertStates[key] = state
			}
			continue
		}
		if state.State == ruleStateFiring {
			// 已不在提醒点：回到 OK（保留 SentLeadDays 供当日重复扫描去重）。
			state.State = ruleStateOK
			state.FiringSince = time.Time{}
			s.alertStates[key] = state
			changed = true
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].NodeID < events[j].NodeID })
	return events, changed
}

// alertCalendarDaysUntil 计算本地日历日差（now → expireAt）。
func alertCalendarDaysUntil(now time.Time, expireAt int64) int {
	expire := time.Unix(expireAt, 0)
	nowDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	expireDay := time.Date(expire.Year(), expire.Month(), expire.Day(), 0, 0, 0, 0, expire.Location())
	return int(expireDay.Sub(nowDay).Hours() / 24)
}

// collectTrafficQuotaEventsLocked 评估流量配额（每分钟）：从 threshold（默认 80）起
// 每 5% 一个台阶，LastStepPct 台阶去重，周期重置清零（见 resetTrafficStepStatesLocked）。
func (s *Store) collectTrafficQuotaEventsLocked(rule AlertRule, now time.Time) ([]RuleAlertEvent, bool) {
	var events []RuleAlertEvent
	changed := false
	startPct := rule.Threshold
	if startPct <= 0 {
		startPct = defaultTrafficStartPct
	}
	for nodeID := range s.nodes {
		profile := s.profiles[nodeID]
		key := ruleStateKey(nodeID, rule.ID)
		if profile == nil || profile.TrafficLimitBytes == 0 || profile.TrafficCounter == nil {
			if _, hasState := s.alertStates[key]; hasState && profile == nil {
				delete(s.alertStates, key)
				changed = true
			}
			continue
		}
		// B-04：与阈值类规则一致，尊重节点总开关与规则范围。
		if !isAlertEnabled(profile) || !ruleScopeMatches(rule.Scope, nodeID, profile) {
			if _, has := s.alertStates[key]; has {
				delete(s.alertStates, key)
				changed = true
			}
			continue
		}
		node := s.nodes[nodeID]
		state, hasState := s.alertStates[key]
		used := trafficUsedBytes(profile)
		pct := float64(used) / float64(profile.TrafficLimitBytes) * 100
		step := trafficQuotaStepFor(pct, startPct)
		display := resolveAlertDisplay(profile, node.Stats, nodeID)
		if step > state.LastStepPct {
			events = append(events, RuleAlertEvent{
				RuleID: rule.ID, NodeID: nodeID, Display: display,
				Value: pct, UsedBytes: used, QuotaBytes: profile.TrafficLimitBytes,
			})
			state.LastStepPct = step
			state.State = ruleStateFiring
			if state.FiringSince.IsZero() {
				state.FiringSince = now
			}
			state.LastNotifiedAt = now
			s.alertStates[key] = state
			changed = true
			continue
		}
		if step > 0 && state.LastStepPct > 0 && ruleNotifyRetryDue(state, now) {
			// 有台阶未送达全部渠道：补发。
			events = append(events, RuleAlertEvent{
				RuleID: rule.ID, NodeID: nodeID, Display: display,
				Value: pct, UsedBytes: used, QuotaBytes: profile.TrafficLimitBytes,
				Delivered: cloneNotifyBoolMap(state.Delivered),
			})
			state.NextRetryAt = time.Time{}
			state.LastNotifiedAt = now
			s.alertStates[key] = state
		}
		if hasState && state.State == ruleStateFiring && step <= 0 {
			// 使用率回到起报线以下：静默回到 OK（无恢复通知）。
			state.State = ruleStateOK
			state.FiringSince = time.Time{}
			s.alertStates[key] = state
			changed = true
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].NodeID < events[j].NodeID })
	return events, changed
}

// trafficQuotaStepFor 返回 pct 当前跨到的最高台阶（pct < start 时为 0，封顶 100）。
func trafficQuotaStepFor(pct, startPct float64) float64 {
	if pct < startPct {
		return 0
	}
	steps := math.Floor((pct - startPct) / trafficQuotaStepPct)
	step := startPct + steps*trafficQuotaStepPct
	if step > trafficQuotaMaxStepPct {
		step = trafficQuotaMaxStepPct
	}
	return step
}

func trafficUsedBytes(profile *NodeProfile) uint64 {
	if profile == nil || profile.TrafficCounter == nil {
		return 0
	}
	counter := profile.TrafficCounter
	switch normalizeTrafficLimitType(profile.TrafficLimitType) {
	case "up":
		return counter.AccSent
	case "down":
		return counter.AccRecv
	case "max":
		return max(counter.AccSent, counter.AccRecv)
	default: // sum
		return counter.AccSent + counter.AccRecv
	}
}

func normalizeTrafficLimitType(raw string) string {
	switch strings.TrimSpace(raw) {
	case "up", "down", "max":
		return strings.TrimSpace(raw)
	default:
		return "sum"
	}
}

func normalizeTrafficResetDay(day int) int {
	if day < 1 || day > 28 {
		return 1
	}
	return day
}

// clearRuleSamplesLocked 清空全部阈值类样本环（规则列表变更后调用：旧样本的
// violated 语义基于旧阈值，继续使用会造成误判；环在后续 tick 内自然重建）。
func (s *Store) clearRuleSamplesLocked() {
	s.ruleSamples = make(map[string][]ruleSample)
}

// deleteRuleAlertStatesForNode 删除某节点的全部规则评估状态（pending deletes 快照用）。
func deleteRuleAlertStatesForNode(states map[string]RuleAlertState, nodeID string) {
	prefix := nodeID + "|"
	for key := range states {
		if strings.HasPrefix(key, prefix) {
			delete(states, key)
		}
	}
}

// resetTrafficStepStatesLocked 在流量周期重置时清零该节点全部 traffic_quota 规则的
// 台阶去重状态（LastStepPct），并让 FIRING 静默回到 OK。
func (s *Store) resetTrafficStepStatesLocked(nodeID string) {
	for _, rule := range s.settings.AlertRules {
		if rule.Metric != alertMetricTrafficQuota {
			continue
		}
		key := ruleStateKey(nodeID, rule.ID)
		state, ok := s.alertStates[key]
		if !ok {
			continue
		}
		state.LastStepPct = 0
		state.State = ruleStateOK
		state.FiringSince = time.Time{}
		state.NextRetryAt = time.Time{}
		state.Delivered = nil
		state.RetryCount = 0
		s.alertStates[key] = state
	}
}

// ===== 流量计数（updateNodeStats 挂钩） =====

// applyTrafficCounterLocked 按增量累加节点月度流量：新值小于上次值（agent 重启回绕）
// 时把新值本身当增量；到达 TrafficResetDay 时清零并重置台阶状态。changed 表示计数
// 数据有变化；cycleReset 表示周期起点确立（计数器创建或跨重置日），调用方仅据此
// 立即落盘——普通累加交给 shouldPersistLocked 节流（B-02）。
// B-01：静态信息上报（StaticInfo=true）同样携带完整的 Network.BytesSent/BytesRecv
// （见 metrics.Collect），不再用它阻断计数。
func (s *Store) applyTrafficCounterLocked(nodeID string, profile *NodeProfile, stats metrics.NodeStats, now time.Time) (changed, cycleReset bool) {
	if profile == nil {
		return false, false
	}
	sent := stats.Network.BytesSent
	recv := stats.Network.BytesRecv
	resetDay := normalizeTrafficResetDay(profile.TrafficResetDay)
	cycleStart := trafficCycleStartFor(now, resetDay)

	counter := profile.TrafficCounter
	if counter == nil {
		profile.TrafficCounter = &TrafficCounter{
			CycleStart: cycleStart.Unix(),
			LastSent:   sent,
			LastRecv:   recv,
		}
		return true, true
	}
	if counter.CycleStart <= 0 || cycleStart.Unix() > counter.CycleStart {
		// 新周期：清零累计，Last 基线切换为当前上报值。
		counter.CycleStart = cycleStart.Unix()
		counter.AccSent = 0
		counter.AccRecv = 0
		counter.LastSent = sent
		counter.LastRecv = recv
		changed = true
		cycleReset = true
		s.resetTrafficStepStatesLocked(nodeID)
	}
	incSent := uint64(0)
	if sent >= counter.LastSent {
		incSent = sent - counter.LastSent
	} else {
		incSent = sent // 回绕：新值本身当增量
	}
	incRecv := uint64(0)
	if recv >= counter.LastRecv {
		incRecv = recv - counter.LastRecv
	} else {
		incRecv = recv
	}
	if incSent > 0 || incRecv > 0 || sent != counter.LastSent || recv != counter.LastRecv {
		if incSent > 0 {
			counter.AccSent += incSent
		}
		if incRecv > 0 {
			counter.AccRecv += incRecv
		}
		counter.LastSent = sent
		counter.LastRecv = recv
		changed = true
	}
	return changed, cycleReset
}

// trafficCycleStartFor 返回 t 所处流量周期的起点（本地时区每月 resetDay 日 00:00）。
func trafficCycleStartFor(t time.Time, resetDay int) time.Time {
	resetDay = normalizeTrafficResetDay(resetDay)
	local := t.Local()
	candidate := time.Date(local.Year(), local.Month(), resetDay, 0, 0, 0, 0, local.Location())
	if candidate.After(local) {
		candidate = time.Date(local.Year(), local.Month()-1, resetDay, 0, 0, 0, 0, local.Location())
	}
	return candidate
}

// ===== 投递与回执 =====

// dispatchRuleBatchNotice 把一个批次按渠道投递（每个渠道只发它尚未送达的事件），
// 返回渠道 ID → 是否全部成功。日志不输出 token / webhook 全文。
func dispatchRuleBatchNotice(batch RuleNoticeBatch) map[string]bool {
	results := make(map[string]bool, len(batch.Channels))
	for _, channel := range batch.Channels {
		owed := owedRuleAlertEvents(batch.Events, channel.ID)
		if len(owed) == 0 {
			results[channel.ID] = true
			continue
		}
		notifier, err := newNotifier(channel)
		var sendErr error
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
			sendErr = notifier.Send(ctx, NotifyMessage{Text: buildRuleNoticeMessage(batch, owed)})
			cancel()
		} else {
			sendErr = err
		}
		if sendErr != nil {
			log.Printf("规则告警发送失败（规则 %s，渠道 %s）: %v", batch.Rule.ID, channel.ID, sendErr)
			results[channel.ID] = false
			continue
		}
		results[channel.ID] = true
	}
	return results
}

func owedRuleAlertEvents(events []RuleAlertEvent, channelID string) []RuleAlertEvent {
	owed := make([]RuleAlertEvent, 0, len(events))
	for _, event := range events {
		if event.Delivered[channelID] {
			continue
		}
		owed = append(owed, event)
	}
	return owed
}

// RecordRuleDelivery 按 results（渠道 ID → 是否成功）记录批次内事件的投递进度：
// 只有全部渠道送达才取消重试；阈值类告警保持 FIRING（等待 Repeat/恢复），恢复与
// 事件类规则（expiry 已过提醒点、流量台阶已记）送达后按各自语义收敛。
func (s *Store) RecordRuleDelivery(batch RuleNoticeBatch, results map[string]bool) {
	needsPersist := false
	s.mu.Lock()
	now := time.Now()
	for _, event := range batch.Events {
		key := ruleStateKey(event.NodeID, event.RuleID)
		state, ok := s.alertStates[key]
		if !ok {
			continue
		}
		for channelID, success := range results {
			if success {
				if state.Delivered == nil {
					state.Delivered = make(map[string]bool)
				}
				state.Delivered[channelID] = true
			}
		}
		allDelivered := len(results) > 0
		for channelID := range results {
			if !state.Delivered[channelID] {
				allDelivered = false
				break
			}
		}
		if allDelivered {
			switch {
			case batch.Kind == ruleNoticeRecovery:
				delete(s.alertStates, key)
			case batch.Rule.Metric == alertMetricExpiry || batch.Rule.Metric == alertMetricTrafficQuota:
				state.RetryCount = 0
				state.NextRetryAt = time.Time{}
				state.Delivered = nil
				s.alertStates[key] = state
			default:
				state.RetryCount = 0
				state.NextRetryAt = time.Time{}
				s.alertStates[key] = state
			}
			needsPersist = true
			continue
		}
		state.RetryCount++
		state.NextRetryAt = now.Add(alertRetryBackoff(state.RetryCount))
		s.alertStates[key] = state
		needsPersist = true
	}
	s.mu.Unlock()
	if needsPersist {
		s.persistLogged()
	}
}

// logRuleNoticeEvents 输出评估事件日志（不含敏感信息）。
func logRuleNoticeEvents(batches []RuleNoticeBatch) {
	for _, batch := range batches {
		for _, event := range batch.Events {
			reportLogger.Printf("[%s] 规则告警（%s/%s）：%s（node=%s）",
				batch.SiteTitle,
				string(batch.Kind),
				batch.Rule.ID,
				formatAlertValue(event.Display, "未命名节点"),
				formatAlertValue(event.NodeID, "unknown"),
			)
		}
	}
}

// ===== 消息泛化（buildEventMessage 四类示例格式） =====

// buildRuleNoticeMessage 组装一个批次的完整消息：单节点时保持文档示例的单行格式，
// 多节点时标题行 + 项目符号行（沿用离线告警的合并做法）。
func buildRuleNoticeMessage(batch RuleNoticeBatch, events []RuleAlertEvent) string {
	siteTitle := normalizeSiteTitle(batch.SiteTitle)
	rule := batch.Rule
	switch rule.Metric {
	case alertMetricExpiry:
		if len(events) == 1 {
			return fmt.Sprintf("⏳ %s 将于 %d 天后到期（%s）", events[0].Display, events[0].Days, events[0].ExpireDate)
		}
		lines := []string{"⏳ 节点到期提醒"}
		for _, event := range events {
			lines = append(lines, fmt.Sprintf("• %s 将于 %d 天后到期（%s）", event.Display, event.Days, event.ExpireDate))
		}
		return strings.Join(lines, "\n")
	case alertMetricTrafficQuota:
		if len(events) == 1 {
			return fmt.Sprintf("📶 %s 本月流量已用 %s（%s / %s）",
				events[0].Display,
				formatTrafficPercent(events[0].Value),
				formatTrafficBytes(events[0].UsedBytes),
				formatTrafficBytes(events[0].QuotaBytes),
			)
		}
		lines := []string{"📶 节点流量提醒"}
		for _, event := range events {
			lines = append(lines, fmt.Sprintf("• %s 本月流量已用 %s（%s / %s）",
				event.Display,
				formatTrafficPercent(event.Value),
				formatTrafficBytes(event.UsedBytes),
				formatTrafficBytes(event.QuotaBytes),
			))
		}
		return strings.Join(lines, "\n")
	}

	meta := alertRuleMetricTable[rule.Metric]
	condition := ruleConditionText(rule)
	if batch.Kind == ruleNoticeRecovery {
		if len(events) == 1 {
			return fmt.Sprintf("【%s】✅ 已恢复 · %s · %s 当前 %s，持续 %s",
				siteTitle, rule.Name, events[0].Display,
				formatRuleMetricValue(rule.Metric, meta, events[0].Value),
				formatAlertDuration(events[0].DurationSec),
			)
		}
		lines := []string{fmt.Sprintf("【%s】✅ 已恢复 · %s", siteTitle, rule.Name)}
		for _, event := range events {
			lines = append(lines, fmt.Sprintf("• %s 当前 %s，持续 %s",
				event.Display,
				formatRuleMetricValue(rule.Metric, meta, event.Value),
				formatAlertDuration(event.DurationSec),
			))
		}
		return strings.Join(lines, "\n")
	}
	if len(events) == 1 {
		return fmt.Sprintf("【%s】⚠️ %s · %s 当前 %s（%s）",
			siteTitle, rule.Name, events[0].Display,
			formatRuleMetricValue(rule.Metric, meta, events[0].Value),
			condition,
		)
	}
	lines := []string{fmt.Sprintf("【%s】⚠️ %s", siteTitle, rule.Name)}
	for _, event := range events {
		lines = append(lines, fmt.Sprintf("• %s 当前 %s（%s）",
			event.Display,
			formatRuleMetricValue(rule.Metric, meta, event.Value),
			condition,
		))
	}
	return strings.Join(lines, "\n")
}

// ruleConditionText 生成「阈值 >90%，持续 5 分钟」这类条件描述。
func ruleConditionText(rule AlertRule) string {
	meta := alertRuleMetricTable[rule.Metric]
	op := ">"
	if rule.Op == alertOpLT {
		op = "<"
	}
	threshold := formatRuleMetricValue(rule.Metric, meta, rule.Threshold)
	condition := fmt.Sprintf("阈值 %s%s", op, threshold)
	if rule.DurationSec > 0 {
		condition += fmt.Sprintf("，持续 %s", formatAlertDuration(rule.DurationSec))
	}
	return condition
}

// formatRuleMetricValue 按指标单位格式化数值；net_in/net_out 以 B/s 存储但按
// Mbps 展示（与 UI 输入口径一致）。
func formatRuleMetricValue(metric string, meta alertMetricMeta, value float64) string {
	switch metric {
	case alertMetricNetIn, alertMetricNetOut:
		return strconv.FormatFloat(value*8/1e6, 'f', 1, 64) + " Mbps"
	case alertMetricLoad1, alertMetricLoad5, alertMetricLoad15:
		return strconv.FormatFloat(value, 'f', 2, 64)
	case alertMetricTCPConn, alertMetricProcessCount:
		return strconv.FormatFloat(value, 'f', 0, 64) + meta.unit
	default:
		return strconv.FormatFloat(value, 'f', 1, 64) + meta.unit
	}
}

func formatTrafficPercent(pct float64) string {
	return strconv.FormatFloat(pct, 'f', 1, 64) + "%"
}

// formatTrafficBytes 输出 850 GB / 1 TB 这类人类可读流量。
func formatTrafficBytes(value uint64) string {
	const tb = 1000 * 1000 * 1000 * 1000
	const gb = 1000 * 1000 * 1000
	const mb = 1000 * 1000
	switch {
	case value >= tb:
		return strconv.FormatFloat(float64(value)/tb, 'f', 1, 64) + " TB"
	case value >= gb:
		return strconv.FormatFloat(float64(value)/gb, 'f', 0, 64) + " GB"
	case value >= mb:
		return strconv.FormatFloat(float64(value)/mb, 'f', 0, 64) + " MB"
	default:
		return strconv.FormatUint(value, 10) + " B"
	}
}

// ===== 模拟评估（preview） =====

// AlertRulePreviewItem 是 preview 接口的单节点结果。
type AlertRulePreviewItem struct {
	NodeID string  `json:"node_id"`
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	State  string  `json:"state"` // pass | fail | unknown
}

const (
	rulePreviewPass    = "pass"
	rulePreviewFail    = "fail"
	rulePreviewUnknown = "unknown"
)

// PreviewAlertRule 对一条规则草稿做单次模拟评估：返回每个适用节点（Scope 匹配且
// 节点告警开关未关）的当前值与三态结论。不修改样本环与状态机。
func (s *Store) PreviewAlertRule(rule AlertRule, now time.Time) ([]AlertRulePreviewItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normalized, err := normalizeAlertRule(rule, s.settings.AlertOfflineSec)
	if err != nil {
		return nil, err
	}

	nodeIDs := make([]string, 0, len(s.nodes))
	for nodeID := range s.nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)

	items := make([]AlertRulePreviewItem, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node := s.nodes[nodeID]
		profile := s.profiles[nodeID]
		if !isAlertEnabled(profile) {
			continue
		}
		if !ruleScopeMatches(normalized.Scope, nodeID, profile) {
			continue
		}
		item := AlertRulePreviewItem{
			NodeID: nodeID,
			Name:   resolveAlertDisplay(profile, node.Stats, nodeID),
			State:  rulePreviewUnknown,
		}
		switch normalized.Metric {
		case alertMetricOffline:
			offlineFor := now.Sub(node.LastSeen).Seconds()
			item.Value = offlineFor
			if offlineFor >= s.offlineAlertThreshold().Seconds() {
				item.State = rulePreviewFail
			} else {
				item.State = rulePreviewPass
			}
		case alertMetricExpiry:
			if profile != nil && profile.ExpireAt > 0 && !profile.AutoRenew {
				daysLeft := alertCalendarDaysUntil(now, profile.ExpireAt)
				item.Value = float64(daysLeft)
				item.State = rulePreviewPass
				for _, day := range alertRuleLeadDays(normalized) {
					if day == daysLeft {
						item.State = rulePreviewFail
						break
					}
				}
			}
		case alertMetricTrafficQuota:
			if profile != nil && profile.TrafficLimitBytes > 0 && profile.TrafficCounter != nil {
				pct := float64(trafficUsedBytes(profile)) / float64(profile.TrafficLimitBytes) * 100
				item.Value = pct
				if pct >= effectiveTrafficStartPct(normalized) {
					item.State = rulePreviewFail
				} else {
					item.State = rulePreviewPass
				}
			}
		default:
			value, known := alertMetricValue(normalized.Metric, normalized.ProbeName, node.Stats)
			offline := now.Sub(node.LastSeen) >= s.offlineAlertThreshold()
			if !known || offline {
				break
			}
			item.Value = value
			if alertValueViolated(normalized, value) {
				item.State = rulePreviewFail
			} else {
				item.State = rulePreviewPass
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func effectiveTrafficStartPct(rule AlertRule) float64 {
	if rule.Threshold > 0 {
		return rule.Threshold
	}
	return defaultTrafficStartPct
}

// ===== tick 节奏（tickRunner 挂钩） =====

// expiryScanDue：启动后立即一次；之后每天本地 09:00 过后的第一次 tick。
func (t *tickRunner) expiryScanDue(now time.Time) bool {
	if t.lastExpiryScan.IsZero() {
		return true
	}
	last := t.lastExpiryScan
	if last.Year() == now.Year() && last.YearDay() == now.YearDay() && last.Location() == now.Location() {
		return false
	}
	nine := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, now.Location())
	return now.After(nine)
}

// trafficEvalDue：每分钟一次。
func (t *tickRunner) trafficEvalDue(now time.Time) bool {
	if t.lastTrafficEval.IsZero() {
		return true
	}
	return now.Sub(t.lastTrafficEval) >= time.Minute
}
