package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultDataDir         = "/data"
	adminTokenLength       = 12
	defaultSiteTitle       = "CyberMonitor"
	defaultHomeTitle       = "CyberMonitor"
	defaultHomeSub         = "主机监控"
	defaultAlertOfflineSec = 300
	testHistoryVersion     = 1
	testHistoryFileName    = "test_history.json"
)

type Settings struct {
	AdminPath            string            `json:"admin_path"`
	AdminUser            string            `json:"admin_user"`
	AdminPass            string            `json:"admin_pass"`
	AdminPassPlain       string            `json:"-"`
	TokenSalt            string            `json:"token_salt,omitempty"`
	AuthToken            string            `json:"auth_token,omitempty"`
	AgentEndpoint        string            `json:"agent_endpoint,omitempty"`
	SiteTitle            string            `json:"site_title,omitempty"`
	SiteIcon             string            `json:"site_icon,omitempty"`
	HomeTitle            string            `json:"home_title,omitempty"`
	HomeSubtitle         string            `json:"home_subtitle,omitempty"`
	AlertWebhook         string            `json:"alert_webhook,omitempty"`
	AlertOfflineSec      int64             `json:"alert_offline_sec,omitempty"`
	AlertAll             bool              `json:"alert_all"`
	AlertNodes           []string          `json:"alert_nodes,omitempty"`
	AlertTelegramToken   string            `json:"alert_telegram_token,omitempty"`
	AlertTelegramUserIDs []int64           `json:"alert_telegram_user_ids,omitempty"`
	AlertTelegramUserID  int64             `json:"alert_telegram_user_id,omitempty"`
	Groups               []string          `json:"groups,omitempty"`
	GroupTree            []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog          []TestCatalogItem `json:"test_catalog,omitempty"`
}

type SettingsView struct {
	AdminPath            string            `json:"admin_path"`
	AdminUser            string            `json:"admin_user"`
	AgentEndpoint        string            `json:"agent_endpoint,omitempty"`
	AgentToken           string            `json:"agent_token,omitempty"`
	SiteTitle            string            `json:"site_title,omitempty"`
	SiteIcon             string            `json:"site_icon,omitempty"`
	HomeTitle            string            `json:"home_title,omitempty"`
	HomeSubtitle         string            `json:"home_subtitle,omitempty"`
	AlertWebhook         string            `json:"alert_webhook,omitempty"`
	AlertOfflineSec      int64             `json:"alert_offline_sec,omitempty"`
	AlertAll             bool              `json:"alert_all"`
	AlertNodes           []string          `json:"alert_nodes,omitempty"`
	AlertTelegramToken   string            `json:"alert_telegram_token,omitempty"`
	AlertTelegramUserIDs []int64           `json:"alert_telegram_user_ids,omitempty"`
	AlertTelegramUserID  int64             `json:"alert_telegram_user_id,omitempty"`
	Commit               string            `json:"commit,omitempty"`
	Groups               []string          `json:"groups,omitempty"`
	GroupTree            []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog          []TestCatalogItem `json:"test_catalog,omitempty"`
}

type SettingsUpdate struct {
	AdminPath            *string            `json:"admin_path"`
	AdminUser            *string            `json:"admin_user"`
	AdminPass            *string            `json:"admin_pass"`
	AgentEndpoint        *string            `json:"agent_endpoint"`
	SiteTitle            *string            `json:"site_title"`
	SiteIcon             *string            `json:"site_icon"`
	HomeTitle            *string            `json:"home_title"`
	HomeSubtitle         *string            `json:"home_subtitle"`
	AlertWebhook         *string            `json:"alert_webhook"`
	AlertOfflineSec      *int64             `json:"alert_offline_sec"`
	AlertAll             *bool              `json:"alert_all"`
	AlertNodes           *[]string          `json:"alert_nodes"`
	AlertTelegramToken   *string            `json:"alert_telegram_token"`
	AlertTelegramUserIDs *[]int64           `json:"alert_telegram_user_ids"`
	AlertTelegramUserID  *int64             `json:"alert_telegram_user_id"`
	Groups               *[]string          `json:"groups"`
	GroupTree            *[]GroupNode       `json:"group_tree"`
	TestCatalog          *[]TestCatalogItem `json:"test_catalog"`
}

type PersistedData struct {
	Settings Settings                `json:"settings"`
	Profiles map[string]*NodeProfile `json:"profiles"`
	Nodes    map[string]NodeState    `json:"nodes,omitempty"`
}

type TestHistoryEntry struct {
	Latency        []*float64 `json:"latency"`
	Loss           []*float64 `json:"loss"`
	Times          []int64    `json:"times"`
	LastAt         int64      `json:"last_at"`
	MinIntervalSec int64      `json:"min_interval_sec,omitempty"`
	AvgIntervalSec float64    `json:"avg_interval_sec,omitempty"`
}

type TestHistoryData struct {
	Version   int                                     `json:"version"`
	UpdatedAt int64                                   `json:"updated_at,omitempty"`
	Nodes     map[string]map[string]*TestHistoryEntry `json:"nodes,omitempty"`
}

type ResetResult struct {
	AdminUser string
	AdminPass string
	AdminPath string
}

func ResetAdminPassword(dataDir string) (ResetResult, error) {
	if strings.TrimSpace(dataDir) == "" {
		return ResetResult{}, errors.New("data dir required")
	}
	dataPath := filepath.Join(dataDir, "state.json")
	payload, loaded, err := loadPersistedData(dataPath)
	if err != nil {
		return ResetResult{}, err
	}
	if !loaded {
		payload.Settings = initSettings(Config{JWTSecret: ""})
		if payload.Profiles == nil {
			payload.Profiles = make(map[string]*NodeProfile)
		}
		if payload.Nodes == nil {
			payload.Nodes = make(map[string]NodeState)
		}
	}
	newPass := randomToken(adminTokenLength)
	newHash, err := hashPassword(newPass)
	if err != nil {
		return ResetResult{}, err
	}
	payload.Settings.AdminPass = newHash
	payload.Settings.TokenSalt = randomToken(adminTokenLength)
	if err := savePersistedData(dataPath, payload); err != nil {
		return ResetResult{}, err
	}
	return ResetResult{
		AdminUser: payload.Settings.AdminUser,
		AdminPass: newPass,
		AdminPath: payload.Settings.AdminPath,
	}, nil
}

type TestCatalogItem struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	IntervalSec int    `json:"interval_sec,omitempty"`
}

type GroupNode struct {
	Name     string      `json:"name"`
	Children []GroupNode `json:"children,omitempty"`
}

func ensureDataDir(dir string) error {
	if dir == "" {
		return errors.New("data dir required")
	}
	return os.MkdirAll(dir, 0o755)
}

func loadPersistedData(path string) (PersistedData, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PersistedData{}, false, nil
		}
		return PersistedData{}, false, err
	}
	var payload PersistedData
	if err := json.Unmarshal(data, &payload); err != nil {
		return PersistedData{}, false, err
	}
	if payload.Profiles == nil {
		payload.Profiles = make(map[string]*NodeProfile)
	}
	if payload.Nodes == nil {
		payload.Nodes = make(map[string]NodeState)
	}
	return payload, true, nil
}

func savePersistedData(path string, payload PersistedData) error {
	if err := ensureDataDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadTestHistoryData(path string) (TestHistoryData, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return TestHistoryData{Nodes: make(map[string]map[string]*TestHistoryEntry)}, false, nil
		}
		return TestHistoryData{}, false, err
	}
	var payload TestHistoryData
	if err := json.Unmarshal(data, &payload); err != nil {
		return TestHistoryData{}, false, err
	}
	if payload.Nodes == nil {
		payload.Nodes = make(map[string]map[string]*TestHistoryEntry)
	}
	return payload, true, nil
}

func saveTestHistoryData(path string, payload TestHistoryData) error {
	if err := ensureDataDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func initSettings(cfg Config) Settings {
	path := strings.TrimSpace(cfg.AdminPath)
	if path == "" {
		path = "/" + randomToken(adminTokenLength)
	} else {
		if normalized, err := normalizeAdminPath(path); err == nil {
			path = normalized
		} else {
			path = "/" + randomToken(adminTokenLength)
		}
	}

	user := strings.TrimSpace(cfg.AdminUser)
	if user == "" {
		user = randomToken(adminTokenLength)
	}
	passHash, passPlain := buildAdminPassword(cfg.AdminPass)

	return Settings{
		AdminPath:            path,
		AdminUser:            user,
		AdminPass:            passHash,
		AdminPassPlain:       passPlain,
		TokenSalt:            randomToken(adminTokenLength),
		AuthToken:            cfg.JWTSecret,
		AgentEndpoint:        "",
		SiteTitle:            defaultSiteTitle,
		SiteIcon:             "",
		HomeTitle:            defaultHomeTitle,
		HomeSubtitle:         defaultHomeSub,
		AlertWebhook:         "",
		AlertOfflineSec:      defaultAlertOfflineSec,
		AlertAll:             true,
		AlertNodes:           []string{},
		AlertTelegramToken:   "",
		AlertTelegramUserIDs: []int64{},
		AlertTelegramUserID:  0,
		Groups:               []string{},
		GroupTree:            []GroupNode{},
		TestCatalog:          []TestCatalogItem{},
	}
}

func buildAdminPassword(input string) (string, string) {
	pass := strings.TrimSpace(input)
	generated := false
	if pass == "" {
		pass = randomToken(adminTokenLength)
		generated = true
	}
	hash, err := hashPassword(pass)
	if err != nil {
		if generated {
			return pass, pass
		}
		return pass, ""
	}
	if generated {
		return hash, pass
	}
	return hash, ""
}

func mergeSettings(existing, fallback Settings) Settings {
	if existing.AdminPath == "" {
		existing.AdminPath = fallback.AdminPath
	}
	if existing.AdminUser == "" {
		existing.AdminUser = fallback.AdminUser
	}
	if existing.AdminPass == "" {
		existing.AdminPass = fallback.AdminPass
	}
	if existing.TokenSalt == "" {
		existing.TokenSalt = fallback.TokenSalt
	}
	if existing.AuthToken == "" {
		existing.AuthToken = fallback.AuthToken
	}
	if existing.AgentEndpoint == "" {
		existing.AgentEndpoint = fallback.AgentEndpoint
	}
	if existing.SiteTitle == "" {
		existing.SiteTitle = fallback.SiteTitle
	}
	if existing.HomeTitle == "" {
		existing.HomeTitle = fallback.HomeTitle
	}
	if existing.HomeSubtitle == "" {
		existing.HomeSubtitle = fallback.HomeSubtitle
	}
	if existing.SiteIcon == "" {
		existing.SiteIcon = fallback.SiteIcon
	}
	if existing.AlertOfflineSec <= 0 {
		existing.AlertOfflineSec = fallback.AlertOfflineSec
	}
	if existing.AlertNodes == nil {
		existing.AlertNodes = fallback.AlertNodes
	}
	if existing.AlertTelegramToken == "" {
		existing.AlertTelegramToken = fallback.AlertTelegramToken
	}
	if len(existing.AlertTelegramUserIDs) == 0 && existing.AlertTelegramUserID > 0 {
		existing.AlertTelegramUserIDs = []int64{existing.AlertTelegramUserID}
	}
	existing.AlertTelegramUserID = 0
	if len(existing.AlertTelegramUserIDs) > 0 {
		existing.AlertTelegramUserIDs = normalizeTelegramUserIDs(existing.AlertTelegramUserIDs)
	}
	if strings.TrimSpace(existing.AlertTelegramToken) == "" || len(existing.AlertTelegramUserIDs) == 0 {
		existing.AlertTelegramToken = ""
		existing.AlertTelegramUserIDs = []int64{}
	}
	if !existing.AlertAll && existing.AlertWebhook == "" && len(existing.AlertNodes) == 0 {
		existing.AlertAll = fallback.AlertAll
	}
	if existing.Groups == nil {
		existing.Groups = fallback.Groups
	}
	if existing.GroupTree == nil || len(existing.GroupTree) == 0 {
		existing.GroupTree = buildGroupTree(existing.Groups)
	}
	if existing.Groups == nil || len(existing.Groups) == 0 || len(existing.GroupTree) > 0 {
		existing.Groups = flattenGroupTree(existing.GroupTree)
	}
	if existing.TestCatalog == nil {
		existing.TestCatalog = fallback.TestCatalog
	}
	return existing
}

func normalizeAdminPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("admin path empty")
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if len(trimmed) > 1 && strings.HasSuffix(trimmed, "/") {
		trimmed = strings.TrimRight(trimmed, "/")
	}
	if trimmed == "/" {
		return "", errors.New("admin path invalid")
	}
	if strings.Contains(trimmed, "..") {
		return "", errors.New("admin path invalid")
	}
	for _, prefix := range []string{"/api", "/assets", "/ws"} {
		if strings.HasPrefix(trimmed, prefix) {
			return "", fmt.Errorf("admin path conflicts with %s", prefix)
		}
	}
	return trimmed, nil
}

func randomToken(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		return ""
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		for i := range bytes {
			bytes[i] = alphabet[r.Intn(len(alphabet))]
		}
		return string(bytes)
	}
	for i, b := range bytes {
		bytes[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(bytes)
}

func normalizeGroups(groups []string) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(groups))
	for _, group := range groups {
		value := strings.TrimSpace(group)
		if value == "" || value == "全部" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func normalizeAlertNodes(nodes []string) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(nodes))
	for _, node := range nodes {
		value := strings.TrimSpace(node)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func normalizeTagValues(tags []string) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(tags))
	for _, tag := range tags {
		value := strings.TrimSpace(tag)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func parseGroupSelection(value string) (string, string) {
	raw := strings.TrimSpace(value)
	if raw == "" || raw == "全部" {
		return "", ""
	}
	group := raw
	tag := ""
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		group = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			tag = strings.TrimSpace(parts[1])
		}
	} else if strings.Contains(raw, "/") {
		parts := strings.SplitN(raw, "/", 2)
		group = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			tag = strings.TrimSpace(parts[1])
		}
	}
	if group == "" || group == "全部" {
		return "", ""
	}
	return group, tag
}

func normalizeGroupSelections(selections []string) []string {
	if len(selections) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	tagsByGroup := make(map[string]map[string]struct{})
	order := make([]string, 0, len(selections))

	for _, raw := range selections {
		group, tag := parseGroupSelection(raw)
		if group == "" {
			continue
		}
		if tag != "" {
			if tagsByGroup[group] == nil {
				tagsByGroup[group] = make(map[string]struct{})
			}
			if _, ok := tagsByGroup[group][tag]; ok {
				continue
			}
			tagsByGroup[group][tag] = struct{}{}
			entry := fmt.Sprintf("%s:%s", group, tag)
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			order = append(order, entry)
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		order = append(order, group)
	}

	if len(tagsByGroup) == 0 {
		return order
	}
	filtered := make([]string, 0, len(order))
	for _, value := range order {
		group, tag := parseGroupSelection(value)
		if group == "" {
			continue
		}
		if tag == "" && len(tagsByGroup[group]) > 0 {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func selectionsFromGroupTags(group string, tags []string) []string {
	group = strings.TrimSpace(group)
	if group == "" || group == "全部" {
		return nil
	}
	normalizedTags := normalizeTagValues(tags)
	if len(normalizedTags) == 0 {
		return []string{group}
	}
	result := make([]string, 0, len(normalizedTags))
	for _, tag := range normalizedTags {
		result = append(result, fmt.Sprintf("%s:%s", group, tag))
	}
	return result
}

func primaryGroupTagsFromSelections(selections []string) (string, []string) {
	normalized := normalizeGroupSelections(selections)
	if len(normalized) == 0 {
		return "", nil
	}
	seenGroup := make(map[string]struct{})
	groupOrder := make([]string, 0, len(normalized))
	tagsByGroup := make(map[string][]string)
	tagsSeen := make(map[string]map[string]struct{})
	for _, value := range normalized {
		group, tag := parseGroupSelection(value)
		if group == "" {
			continue
		}
		if _, ok := seenGroup[group]; !ok {
			seenGroup[group] = struct{}{}
			groupOrder = append(groupOrder, group)
		}
		if tag == "" {
			continue
		}
		if tagsSeen[group] == nil {
			tagsSeen[group] = make(map[string]struct{})
		}
		if _, ok := tagsSeen[group][tag]; ok {
			continue
		}
		tagsSeen[group][tag] = struct{}{}
		tagsByGroup[group] = append(tagsByGroup[group], tag)
	}
	if len(groupOrder) == 0 {
		return "", nil
	}
	primary := groupOrder[0]
	return primary, tagsByGroup[primary]
}

func normalizeGroupTree(nodes []GroupNode) []GroupNode {
	seen := make(map[string]struct{})
	normalized := make([]GroupNode, 0, len(nodes))
	for _, node := range nodes {
		name := strings.TrimSpace(node.Name)
		if name == "" || name == "全部" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		children := normalizeTagNodes(node.Children)
		normalized = append(normalized, GroupNode{
			Name:     name,
			Children: children,
		})
	}
	return normalized
}

func normalizeTagNodes(nodes []GroupNode) []GroupNode {
	seen := make(map[string]struct{})
	var tags []GroupNode
	var walk func(items []GroupNode)
	walk = func(items []GroupNode) {
		for _, item := range items {
			name := strings.TrimSpace(item.Name)
			if name == "" || name == "全部" {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				tags = append(tags, GroupNode{Name: name})
			}
			if len(item.Children) > 0 {
				walk(item.Children)
			}
		}
	}
	walk(nodes)
	return tags
}

func flattenGroupTree(nodes []GroupNode) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range nodes {
		name := strings.TrimSpace(item.Name)
		if name == "" || name == "全部" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func buildGroupTree(groups []string) []GroupNode {
	var root []GroupNode
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" || trimmed == "全部" {
			continue
		}
		parts := strings.Split(trimmed, "/")
		groupName := strings.TrimSpace(parts[0])
		if groupName == "" {
			continue
		}
		index := -1
		for i := range root {
			if root[i].Name == groupName {
				index = i
				break
			}
		}
		if index == -1 {
			root = append(root, GroupNode{Name: groupName})
			index = len(root) - 1
		}
		if len(parts) > 1 {
			tag := strings.TrimSpace(strings.Join(parts[1:], "/"))
			if tag != "" {
				root[index].Children = append(root[index].Children, GroupNode{Name: tag})
			}
		}
	}
	return normalizeGroupTree(root)
}

func normalizeTestCatalog(items []TestCatalogItem) ([]TestCatalogItem, error) {
	seen := make(map[string]struct{})
	normalized := make([]TestCatalogItem, 0, len(items))
	for _, item := range items {
		host := strings.TrimSpace(item.Host)
		if host == "" {
			return nil, errors.New("测试节点地址不能为空")
		}
		if hasUnsafeText(host) {
			return nil, errors.New("测试节点地址包含非法字符")
		}
		if !isValidTestHost(host) {
			return nil, errors.New("测试节点地址格式不正确")
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, errors.New("测试节点名称不能为空")
		}
		if hasUnsafeText(name) {
			return nil, errors.New("测试节点名称包含非法字符")
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "icmp" && itemType != "tcp" {
			if item.Port > 0 {
				itemType = "tcp"
			} else {
				itemType = "icmp"
			}
		}
		port := item.Port
		if itemType == "icmp" {
			port = 0
		} else if port <= 0 || port > 65535 {
			return nil, errors.New("TCP 端口需为 1-65535")
		}
		interval := 0
		if itemType == "tcp" {
			interval = item.IntervalSec
			if interval < 0 {
				interval = 0
			}
			if interval > 3600 {
				interval = 3600
			}
		}
		id := strings.TrimSpace(item.ID)
		if id == "" {
			id = randomToken(10)
		}
		for {
			if _, ok := seen[id]; !ok {
				break
			}
			id = randomToken(10)
		}
		seen[id] = struct{}{}
		normalized = append(normalized, TestCatalogItem{
			ID:          id,
			Name:        name,
			Type:        itemType,
			Host:        host,
			Port:        port,
			IntervalSec: interval,
		})
	}
	return normalized, nil
}

func hasUnsafeText(value string) bool {
	return strings.ContainsAny(value, "<>\"'`")
}

func isValidTestHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") || strings.Contains(host, " ") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return isValidHostname(host)
}

func isValidHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
