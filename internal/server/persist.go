package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

const (
	adminTokenLength       = 12
	tokenAlphabet          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	defaultSiteTitle       = "CyberMonitor"
	defaultHomeTitle       = "CyberMonitor"
	defaultHomeSub         = "主机监控"
	defaultAlertOfflineSec = 300
	defaultLoginFailLimit  = 5
	defaultLoginFailWindow = 15 * 60
	defaultLoginLockSec    = 15 * 60
	testHistoryVersion     = 1
	testHistoryFileName    = "test_history.json"
	configExportVersion    = 1
	maxTestCatalogItems    = 512
)

type Settings struct {
	AdminPath            string            `json:"admin_path"`
	AdminUser            string            `json:"admin_user"`
	AdminPass            string            `json:"admin_pass"`
	AdminPassPlain       string            `json:"-"`
	TurnstileSiteKey     string            `json:"turnstile_site_key,omitempty"`
	TurnstileSecretKey   string            `json:"turnstile_secret_key,omitempty"`
	TokenSalt            string            `json:"token_salt,omitempty"`
	AuthToken            string            `json:"auth_token,omitempty"`
	AgentToken           string            `json:"agent_token,omitempty"`
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
	LoginFailLimit       int               `json:"login_fail_limit,omitempty"`
	LoginFailWindowSec   int64             `json:"login_fail_window_sec,omitempty"`
	LoginLockSec         int64             `json:"login_lock_sec,omitempty"`
	AISettings           AISettings        `json:"ai_settings,omitempty"`
	Groups               []string          `json:"groups,omitempty"`
	GroupTree            []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog          []TestCatalogItem `json:"test_catalog,omitempty"`
}

type SettingsView struct {
	AdminPath            string            `json:"admin_path"`
	AdminUser            string            `json:"admin_user"`
	TurnstileSiteKey     string            `json:"turnstile_site_key,omitempty"`
	TurnstileSecretKey   string            `json:"turnstile_secret_key,omitempty"`
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
	LoginFailLimit       int               `json:"login_fail_limit,omitempty"`
	LoginFailWindowSec   int64             `json:"login_fail_window_sec,omitempty"`
	LoginLockSec         int64             `json:"login_lock_sec,omitempty"`
	AISettings           AISettings        `json:"ai_settings,omitempty"`
	Version              string            `json:"version,omitempty"`
	Commit               string            `json:"commit,omitempty"`
	Groups               []string          `json:"groups,omitempty"`
	GroupTree            []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog          []TestCatalogItem `json:"test_catalog,omitempty"`
	SessionToken         string            `json:"session_token,omitempty"`
	SessionExpiresAt     int64             `json:"session_expires_at,omitempty"`
}

type SettingsUpdate struct {
	AdminPath            *string            `json:"admin_path"`
	AdminUser            *string            `json:"admin_user"`
	AdminPass            *string            `json:"admin_pass"`
	TurnstileSiteKey     *string            `json:"turnstile_site_key"`
	TurnstileSecretKey   *string            `json:"turnstile_secret_key"`
	AgentToken           *string            `json:"agent_token"`
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
	LoginFailLimit       *int               `json:"login_fail_limit"`
	LoginFailWindowSec   *int64             `json:"login_fail_window_sec"`
	LoginLockSec         *int64             `json:"login_lock_sec"`
	AISettings           *AISettings        `json:"ai_settings"`
	Groups               *[]string          `json:"groups"`
	GroupTree            *[]GroupNode       `json:"group_tree"`
	TestCatalog          *[]TestCatalogItem `json:"test_catalog"`
}

type PersistedData struct {
	Settings        Settings                       `json:"settings"`
	Profiles        map[string]*NodeProfile        `json:"profiles"`
	Nodes           map[string]NodeState           `json:"nodes,omitempty"`
	OfflineSessions map[string]OfflineSessionState `json:"offline_sessions,omitempty"`
}

type legacyPersistedProfile struct {
	Tests []metrics.NetworkTestConfig `json:"tests,omitempty"`
}

type OfflineSessionState struct {
	StartedAt int64 `json:"started_at"`
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

type ConfigTransferData struct {
	Version    int                     `json:"version"`
	ExportedAt int64                   `json:"exported_at"`
	Settings   SettingsView            `json:"settings"`
	Profiles   map[string]*NodeProfile `json:"profiles,omitempty"`
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
		payload = applyPersistedDataDefaults(payload)
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

func normalizeJSONBytes(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	return bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
}

func decodeFirstJSONValue(data []byte, target any) (bool, error) {
	normalized := normalizeJSONBytes(data)
	if len(normalized) == 0 {
		return false, io.EOF
	}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	if err := decoder.Decode(target); err != nil {
		return false, err
	}
	rest := bytes.TrimSpace(normalized[decoder.InputOffset():])
	return len(rest) > 0, nil
}

func strictUnmarshalJSON(data []byte, target any) error {
	trailing, err := decodeFirstJSONValue(data, target)
	if err != nil {
		return err
	}
	if trailing {
		return errors.New("extra content after JSON value")
	}
	return nil
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
	if err := strictUnmarshalJSON(data, &payload); err != nil {
		return PersistedData{}, false, err
	}
	if err := migrateLegacyProfileTests(data, &payload); err != nil {
		return PersistedData{}, false, err
	}
	return applyPersistedDataDefaults(payload), true, nil
}

func savePersistedData(path string, payload PersistedData) error {
	return writeJSONFileAtomic(path, payload)
}

func loadTestHistoryData(path string) (TestHistoryData, bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return TestHistoryData{Nodes: make(map[string]map[string]*TestHistoryEntry)}, false, false, nil
		}
		return TestHistoryData{}, false, false, err
	}

	var payload TestHistoryData
	trailing, err := decodeFirstJSONValue(data, &payload)
	if err == nil {
		if payload.Version == 0 && payload.UpdatedAt == 0 && payload.Nodes == nil {
			var legacy map[string]map[string]*TestHistoryEntry
			legacyTrailing, legacyErr := decodeFirstJSONValue(data, &legacy)
			if legacyErr == nil {
				payload = TestHistoryData{
					Version:   testHistoryVersion,
					UpdatedAt: time.Now().Unix(),
					Nodes:     legacy,
				}
				trailing = trailing || legacyTrailing || legacy != nil
			}
		}
	} else {
		var legacy map[string]map[string]*TestHistoryEntry
		legacyTrailing, legacyErr := decodeFirstJSONValue(data, &legacy)
		if legacyErr != nil {
			return TestHistoryData{}, false, false, err
		}
		payload = TestHistoryData{
			Version:   testHistoryVersion,
			UpdatedAt: time.Now().Unix(),
			Nodes:     legacy,
		}
		trailing = legacyTrailing || legacy != nil
	}
	if payload.Nodes == nil {
		payload.Nodes = make(map[string]map[string]*TestHistoryEntry)
	}
	needsRewrite := trailing
	if payload.Version != testHistoryVersion {
		payload.Version = testHistoryVersion
		needsRewrite = true
	}
	for _, tests := range payload.Nodes {
		for _, entry := range tests {
			if entry == nil {
				continue
			}
			beforeLatency := len(entry.Latency)
			beforeLoss := len(entry.Loss)
			beforeTimes := len(entry.Times)
			normalizeHistoryEntry(entry)
			if len(entry.Latency) != beforeLatency || len(entry.Loss) != beforeLoss || len(entry.Times) != beforeTimes {
				needsRewrite = true
			}
		}
	}
	return payload, true, needsRewrite, nil
}

func applyPersistedDataDefaults(payload PersistedData) PersistedData {
	if payload.Profiles == nil {
		payload.Profiles = make(map[string]*NodeProfile)
	}
	if payload.Nodes == nil {
		payload.Nodes = make(map[string]NodeState)
	}
	if payload.OfflineSessions == nil {
		payload.OfflineSessions = make(map[string]OfflineSessionState)
	}
	return payload
}

func migrateLegacyProfileTests(data []byte, payload *PersistedData) error {
	if payload == nil || len(payload.Profiles) == 0 {
		return nil
	}

	legacyTests, err := readLegacyProfileTests(data)
	if err != nil {
		return err
	}
	if len(legacyTests) == 0 {
		return nil
	}

	if payload.Settings.TestCatalog == nil {
		payload.Settings.TestCatalog = []TestCatalogItem{}
	}
	catalogIndex := legacyTestCatalogIndex(payload.Settings.TestCatalog)

	for nodeID, tests := range legacyTests {
		if len(tests) == 0 {
			continue
		}
		profile := payload.Profiles[nodeID]
		if profile == nil || len(profile.TestSelections) > 0 {
			continue
		}
		selections := make([]TestSelection, 0, len(tests))
		seenSelections := make(map[string]struct{}, len(tests))
		for _, test := range tests {
			item, ok := legacyTestCatalogItem(test, catalogIndex)
			if !ok {
				continue
			}
			if item.ID == "" {
				item.ID = randomToken(10)
				payload.Settings.TestCatalog = append(payload.Settings.TestCatalog, item)
				catalogIndex[legacyTestCatalogKey(item.Name, item.Type, item.Host, item.Port)] = item
			}
			if _, exists := seenSelections[item.ID]; exists {
				continue
			}
			seenSelections[item.ID] = struct{}{}
			selections = append(selections, TestSelection{
				TestID:      item.ID,
				IntervalSec: test.IntervalSec,
			})
		}
		if len(selections) > 0 {
			profile.TestSelections = selections
		}
	}
	return nil
}

func readLegacyProfileTests(data []byte) (map[string][]metrics.NetworkTestConfig, error) {
	var raw struct {
		Profiles map[string]json.RawMessage `json:"profiles"`
	}
	if err := strictUnmarshalJSON(data, &raw); err != nil {
		return nil, err
	}
	if len(raw.Profiles) == 0 {
		return nil, nil
	}

	result := make(map[string][]metrics.NetworkTestConfig)
	for nodeID, rawProfile := range raw.Profiles {
		var profile legacyPersistedProfile
		if err := strictUnmarshalJSON(rawProfile, &profile); err != nil {
			return nil, err
		}
		if len(profile.Tests) > 0 {
			result[nodeID] = profile.Tests
		}
	}
	return result, nil
}

func legacyTestCatalogIndex(items []TestCatalogItem) map[string]TestCatalogItem {
	index := make(map[string]TestCatalogItem, len(items))
	for _, item := range items {
		key := legacyTestCatalogKey(item.Name, item.Type, item.Host, item.Port)
		if key == "" {
			continue
		}
		if _, exists := index[key]; !exists {
			index[key] = item
		}
	}
	return index
}

func legacyTestCatalogItem(test metrics.NetworkTestConfig, index map[string]TestCatalogItem) (TestCatalogItem, bool) {
	candidate := TestCatalogItem{
		Name:        strings.TrimSpace(test.Name),
		Type:        strings.ToLower(strings.TrimSpace(test.Type)),
		Host:        strings.TrimSpace(test.Host),
		Port:        test.Port,
		IntervalSec: test.IntervalSec,
	}
	if candidate.Host == "" {
		return TestCatalogItem{}, false
	}
	if candidate.Type != "icmp" && candidate.Type != "tcp" {
		if candidate.Port > 0 {
			candidate.Type = "tcp"
		} else {
			candidate.Type = "icmp"
		}
	}
	if candidate.Type == "icmp" {
		candidate.Port = 0
	}
	if candidate.Name == "" {
		candidate.Name = candidate.Host
	}
	key := legacyTestCatalogKey(candidate.Name, candidate.Type, candidate.Host, candidate.Port)
	if item, ok := index[key]; ok {
		return item, true
	}
	normalized, err := normalizeTestCatalog([]TestCatalogItem{candidate})
	if err != nil || len(normalized) == 0 {
		return TestCatalogItem{}, false
	}
	normalized[0].ID = ""
	return normalized[0], true
}

func legacyTestCatalogKey(name, testType, host string, port int) string {
	kind := strings.ToLower(strings.TrimSpace(testType))
	trimmedHost := strings.TrimSpace(host)
	trimmedName := strings.TrimSpace(name)
	if trimmedHost == "" {
		return ""
	}
	if kind == "icmp" {
		port = 0
	}
	return strings.ToLower(fmt.Sprintf("%s|%s|%s|%d", trimmedName, kind, trimmedHost, port))
}

func writeJSONFileAtomic(path string, payload any) error {
	dir := filepath.Dir(path)
	if err := ensureDataDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	syncParentDir(dir)
	return nil
}

func syncParentDir(dir string) {
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

func cloneProfiles(profiles map[string]*NodeProfile) map[string]*NodeProfile {
	if len(profiles) == 0 {
		return map[string]*NodeProfile{}
	}
	cloned := make(map[string]*NodeProfile, len(profiles))
	for id, profile := range profiles {
		if profile == nil {
			continue
		}
		copyProfile := *profile
		copyProfile.Tags = cloneStringSlice(profile.Tags)
		copyProfile.Groups = cloneStringSlice(profile.Groups)
		copyProfile.TestSelections = cloneTestSelections(profile.TestSelections)
		copyProfile.AgentUpdate = cloneAgentUpdateInstruction(profile.AgentUpdate)
		if profile.AlertEnabled != nil {
			value := *profile.AlertEnabled
			copyProfile.AlertEnabled = &value
		}
		cloned[id] = &copyProfile
	}
	return cloned
}

func cloneProfilesForExport(profiles map[string]*NodeProfile) map[string]*NodeProfile {
	cloned := cloneProfiles(profiles)
	for _, profile := range cloned {
		if profile != nil {
			profile.AgentAuthToken = ""
		}
	}
	return cloned
}

func cloneOfflineSessions(sessions map[string]OfflineSessionState) map[string]OfflineSessionState {
	if len(sessions) == 0 {
		return map[string]OfflineSessionState{}
	}
	cloned := make(map[string]OfflineSessionState, len(sessions))
	for nodeID, session := range sessions {
		cloned[nodeID] = session
	}
	return cloned
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
		AgentToken:           cfg.AgentToken,
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
		LoginFailLimit:       defaultLoginFailLimit,
		LoginFailWindowSec:   defaultLoginFailWindow,
		LoginLockSec:         defaultLoginLockSec,
		AISettings:           defaultAISettings(),
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
	mergeString := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	mergeInt64 := func(dst *int64, src int64) {
		if *dst <= 0 {
			*dst = src
		}
	}
	mergeInt := func(dst *int, src int) {
		if *dst == 0 {
			*dst = src
		}
	}

	mergeString(&existing.AdminPath, fallback.AdminPath)
	mergeString(&existing.AdminUser, fallback.AdminUser)
	mergeString(&existing.AdminPass, fallback.AdminPass)
	mergeString(&existing.TokenSalt, fallback.TokenSalt)

	if existing.AgentToken == "" && existing.AuthToken != "" {
		existing.AgentToken = existing.AuthToken
		if fallback.AuthToken != "" && fallback.AuthToken != existing.AuthToken {
			existing.AuthToken = fallback.AuthToken
		}
	}
	mergeString(&existing.AuthToken, fallback.AuthToken)
	mergeString(&existing.AgentToken, fallback.AgentToken)
	mergeString(&existing.AgentEndpoint, fallback.AgentEndpoint)
	mergeString(&existing.SiteTitle, fallback.SiteTitle)
	mergeString(&existing.HomeTitle, fallback.HomeTitle)
	mergeString(&existing.HomeSubtitle, fallback.HomeSubtitle)
	mergeString(&existing.SiteIcon, fallback.SiteIcon)
	mergeString(&existing.AlertTelegramToken, fallback.AlertTelegramToken)

	mergeInt64(&existing.AlertOfflineSec, fallback.AlertOfflineSec)
	mergeInt64(&existing.LoginFailWindowSec, fallback.LoginFailWindowSec)
	mergeInt64(&existing.LoginLockSec, fallback.LoginLockSec)
	mergeInt(&existing.LoginFailLimit, fallback.LoginFailLimit)

	if existing.AlertNodes == nil {
		existing.AlertNodes = fallback.AlertNodes
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

	existing.AISettings = mergeAISettings(existing.AISettings, fallback.AISettings)

	if existing.Groups == nil {
		existing.Groups = fallback.Groups
	}
	if len(existing.GroupTree) == 0 {
		existing.GroupTree = buildGroupTree(existing.Groups)
	}
	existing.Groups = flattenGroupTree(existing.GroupTree)

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
	if length <= 0 {
		return ""
	}
	limit := byte(256 - 256%len(tokenAlphabet))
	out := make([]byte, 0, length)
	buf := make([]byte, length)
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("crypto random failed: %v", err))
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, tokenAlphabet[int(b)%len(tokenAlphabet)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out)
}

func normalizeUniqueStrings(values []string, skip func(string) bool) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || (skip != nil && skip(value)) {
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

func normalizeGroups(groups []string) []string {
	return normalizeUniqueStrings(groups, func(value string) bool {
		return value == "全部"
	})
}

func normalizeAlertNodes(nodes []string) []string {
	return normalizeUniqueStrings(nodes, nil)
}

func normalizeTagValues(tags []string) []string {
	return normalizeUniqueStrings(tags, nil)
}

func normalizeGroupName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "全部" {
		return ""
	}
	return trimmed
}

func canonicalGroupSelection(group, tag string) string {
	if tag == "" {
		return group
	}
	return group + ":" + tag
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
	group = normalizeGroupName(group)
	if group == "" {
		return "", ""
	}
	return group, tag
}

func normalizeGroupSelections(selections []string) []string {
	if len(selections) == 0 {
		return nil
	}
	type selectionEntry struct {
		group string
		tag   string
	}

	seen := make(map[string]struct{})
	tagsByGroup := make(map[string]map[string]struct{})
	entries := make([]selectionEntry, 0, len(selections))

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
			entry := canonicalGroupSelection(group, tag)
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			entries = append(entries, selectionEntry{group: group, tag: tag})
			continue
		}
		entry := canonicalGroupSelection(group, "")
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, selectionEntry{group: group})
	}

	if len(tagsByGroup) == 0 {
		normalized := make([]string, 0, len(entries))
		for _, entry := range entries {
			normalized = append(normalized, canonicalGroupSelection(entry.group, entry.tag))
		}
		return normalized
	}
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.tag == "" && len(tagsByGroup[entry.group]) > 0 {
			continue
		}
		filtered = append(filtered, canonicalGroupSelection(entry.group, entry.tag))
	}
	return filtered
}

func selectionsFromGroupTags(group string, tags []string) []string {
	group = normalizeGroupName(group)
	if group == "" {
		return nil
	}
	normalizedTags := normalizeTagValues(tags)
	if len(normalizedTags) == 0 {
		return []string{group}
	}
	result := make([]string, 0, len(normalizedTags))
	for _, tag := range normalizedTags {
		result = append(result, canonicalGroupSelection(group, tag))
	}
	return result
}

func primaryGroupTagsFromNormalizedSelections(selections []string) (string, []string, bool) {
	if len(selections) == 0 {
		return "", nil, true
	}

	seenEntries := make(map[string]struct{}, len(selections))
	standaloneGroups := make(map[string]struct{}, len(selections))
	tagsSeen := make(map[string]map[string]struct{})
	tagsByGroup := make(map[string][]string)
	primary := ""

	for _, value := range selections {
		raw := strings.TrimSpace(value)
		if raw == "" || raw == "全部" {
			return "", nil, false
		}

		group, tag := parseGroupSelection(raw)
		if group == "" {
			return "", nil, false
		}

		canonical := canonicalGroupSelection(group, tag)
		if raw != canonical {
			return "", nil, false
		}
		if _, ok := seenEntries[canonical]; ok {
			return "", nil, false
		}
		seenEntries[canonical] = struct{}{}

		if primary == "" {
			primary = group
		}

		if tag == "" {
			if _, ok := tagsSeen[group]; ok {
				return "", nil, false
			}
			standaloneGroups[group] = struct{}{}
			continue
		}
		if _, ok := standaloneGroups[group]; ok {
			return "", nil, false
		}
		if tagsSeen[group] == nil {
			tagsSeen[group] = make(map[string]struct{})
		}
		if _, ok := tagsSeen[group][tag]; ok {
			return "", nil, false
		}
		tagsSeen[group][tag] = struct{}{}
		tagsByGroup[group] = append(tagsByGroup[group], tag)
	}

	return primary, tagsByGroup[primary], true
}

func primaryGroupTagsFromSelections(selections []string) (string, []string) {
	if len(selections) == 0 {
		return "", nil
	}

	if group, tags, ok := primaryGroupTagsFromNormalizedSelections(selections); ok {
		return group, tags
	}

	normalized := normalizeGroupSelections(selections)
	if len(normalized) == 0 {
		return "", nil
	}
	group, tags, _ := primaryGroupTagsFromNormalizedSelections(normalized)
	return group, tags
}

func normalizeGroupTree(nodes []GroupNode) []GroupNode {
	seen := make(map[string]struct{})
	normalized := make([]GroupNode, 0, len(nodes))
	for _, node := range nodes {
		name := normalizeGroupName(node.Name)
		if name == "" {
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
			name := normalizeGroupName(item.Name)
			if name == "" {
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
		name := normalizeGroupName(item.Name)
		if name == "" {
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
		groupName := normalizeGroupName(parts[0])
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
			tag := normalizeGroupName(strings.Join(parts[1:], "/"))
			if tag != "" {
				root[index].Children = append(root[index].Children, GroupNode{Name: tag})
			}
		}
	}
	return normalizeGroupTree(root)
}

func normalizeTestCatalog(items []TestCatalogItem) ([]TestCatalogItem, error) {
	if len(items) > maxTestCatalogItems {
		return nil, fmt.Errorf("测试节点数量不能超过 %d 个", maxTestCatalogItems)
	}
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
