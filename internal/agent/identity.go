package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	defaultNodeIDFileName     = ".cybermonitor-node-id"
	defaultAgentTokenFileName = ".cybermonitor-agent-token"
)

type NodeIDOptions struct {
	Explicit     string
	ExplicitFile string
	IsDocker     bool
	HostRoot     string
}

type nodeRegisterResponse struct {
	NodeID     string `json:"node_id"`
	AgentToken string `json:"agent_token"`
}

var newRandomNodeUUID = uuid.NewRandom

func ResolveAgentTokenFilePath(explicit string) (string, error) {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed, nil
	}
	return defaultAgentTokenHomePath()
}

func defaultStateHomePath(fileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	home = strings.TrimSpace(home)
	if home == "" {
		return "", fmt.Errorf("resolve home dir: empty home dir")
	}
	return filepath.Join(home, fileName), nil
}

func ResolveOrCreateNodeIDWithOptions(opts NodeIDOptions) (string, error) {
	opts = normalizeNodeIDOptions(opts)
	nodeID, err := resolveNodeID(opts)
	if err == nil {
		return nodeID, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	targetPath, err := resolveNodeIDCreatePath(opts)
	if err != nil {
		return "", err
	}

	nodeID, err = generateRandomNodeUUID()
	if err != nil {
		return "", err
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", fmt.Errorf("generated node id is empty")
	}
	if err := writeTrimmedFile(targetPath, nodeID); err != nil {
		return "", err
	}
	return nodeID, nil
}

func normalizeNodeIDOptions(opts NodeIDOptions) NodeIDOptions {
	opts.Explicit = strings.TrimSpace(opts.Explicit)
	opts.ExplicitFile = strings.TrimSpace(opts.ExplicitFile)
	opts.HostRoot = strings.TrimSpace(opts.HostRoot)
	return opts
}

func resolveNodeID(opts NodeIDOptions) (string, error) {
	if opts.Explicit != "" {
		return opts.Explicit, nil
	}

	if opts.ExplicitFile != "" {
		return readTrimmedFile(opts.ExplicitFile)
	}

	homePath, homeErr := defaultNodeIDHomePath()
	if homeErr == nil {
		value, err := readTrimmedFile(homePath)
		switch {
		case err == nil:
			return value, nil
		case errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrInvalid):
			// 文件不存在或为空：默认 home 路径继续走指纹派生/重建
			// （显式 -node-id-file 的硬失败语义不受影响）。
		default:
			return "", err
		}
	}

	if opts.IsDocker {
		value, err := resolveStableDockerNodeID(opts.HostRoot)
		switch {
		case err == nil:
			return value, nil
		case !errors.Is(err, os.ErrNotExist):
			return "", err
		}
	}

	return "", os.ErrNotExist
}

func resolveNodeIDCreatePath(opts NodeIDOptions) (string, error) {
	if opts.ExplicitFile != "" {
		return opts.ExplicitFile, nil
	}
	return defaultNodeIDHomePath()
}

func defaultNodeIDHomePath() (string, error) {
	return defaultStateHomePath(defaultNodeIDFileName)
}

func defaultAgentTokenHomePath() (string, error) {
	return defaultStateHomePath(defaultAgentTokenFileName)
}

func resolveStableDockerNodeID(hostRoot string) (string, error) {
	fingerprint, err := readStableHostFingerprint(hostRoot)
	if err != nil {
		return "", err
	}
	return deriveStableNodeIDFromFingerprint(fingerprint), nil
}

func readStableHostFingerprint(hostRoot string) (string, error) {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		return "", os.ErrNotExist
	}

	type fingerprintSource struct {
		label string
		path  string
	}

	sources := []fingerprintSource{
		{label: "machine-id", path: filepath.Join(root, "etc", "machine-id")},
		{label: "dbus-machine-id", path: filepath.Join(root, "var", "lib", "dbus", "machine-id")},
		{label: "product-uuid", path: filepath.Join(root, "sys", "class", "dmi", "id", "product_uuid")},
		{label: "product-serial", path: filepath.Join(root, "sys", "class", "dmi", "id", "product_serial")},
		{label: "board-serial", path: filepath.Join(root, "sys", "class", "dmi", "id", "board_serial")},
		{label: "hostname", path: filepath.Join(root, "etc", "hostname")},
	}

	// 存在但不可读（sysfs product_uuid 等为 0400，非特权容器 EACCES）的
	// 源不参与指纹：与占位符方案相比，指纹值与旧版本（同样跳过）一致，
	// 版本升级不产生节点 ID 漂移；代价是权限状态变化（如改用
	// --privileged）会漂移一次，两方案在此等价。日志点名该源，避免静默。
	var readable, placeholders []string
	for _, source := range sources {
		value, err := readTrimmedFile(source.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) {
				continue
			}
			log.Printf("机器指纹源 %s 不可读，指纹跳过该源: %v", source.path, err)
			placeholders = append(placeholders, source.label+"=<unreadable>")
			continue
		}
		readable = append(readable, source.label+"="+value)
	}
	if len(readable) > 0 {
		return strings.Join(readable, "\n"), nil
	}
	if len(placeholders) > 0 {
		// 全部源存在但均不可读：以占位符参与指纹，保证每次启动派生
		// 同一 ID，不退化为每启动一个随机 UUID。
		return strings.Join(placeholders, "\n"), nil
	}
	// 全部源不存在：hostRoot 未挂载或配置错误的典型症状。此时上层会
	// 生成随机 node ID（容器重建即换新 ID），点名日志让这一后果可见。
	log.Printf("机器指纹源目录 %s 下无可读指纹源，将退回随机 node id（请检查宿主机目录挂载）", root)
	return "", os.ErrNotExist
}

func deriveStableNodeIDFromFingerprint(fingerprint string) string {
	return uuid.NewSHA1(
		uuid.NameSpaceURL,
		[]byte("cybermonitor-node:"+strings.TrimSpace(fingerprint)),
	).String()
}

func loadPersistedAgentToken(filePath string) (string, error) {
	return readTrimmedFile(filePath)
}

func persistAgentToken(filePath, token string) error {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return fmt.Errorf("agent token is empty")
	}
	return writeTrimmedFile(filePath, trimmed)
}

func registerNodeToken(ctx context.Context, client *http.Client, endpoint, nodeID, bootstrapToken string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	bootstrapToken = strings.TrimSpace(bootstrapToken)
	if nodeID == "" {
		return "", fmt.Errorf("node id required")
	}
	if bootstrapToken == "" {
		return "", fmt.Errorf("bootstrap token required")
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("register endpoint 无效: %w", err)
	}
	query := target.Query()
	query.Set("node_id", nodeID)
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-AGENT-TOKEN", bootstrapToken)
	var payload nodeRegisterResponse
	if err := performAgentRequest(client, req, "register", func(body io.Reader) error {
		return decodeAgentResponseJSON(body, &payload, "register response has trailing data")
	}); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.AgentToken) == "" {
		return "", fmt.Errorf("register response missing agent token")
	}
	return strings.TrimSpace(payload.AgentToken), nil
}

func readTrimmedFile(filePath string) (string, error) {
	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return "", os.ErrNotExist
	}
	data, err := os.ReadFile(trimmedPath)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		// 文件存在但为空/全空白：与"不存在"区分开，调用方（显式
		// node-id-file 场景）才不会静默落到其他来源并以别的 ID 上报。
		return "", fmt.Errorf("文件 %s 内容为空: %w", trimmedPath, os.ErrInvalid)
	}
	return trimmed, nil
}

func writeTrimmedFile(filePath, value string) error {
	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return fmt.Errorf("file path required")
	}
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return fmt.Errorf("file value required")
	}
	dir := filepath.Dir(trimmedPath)
	// 目录已存在时不改权限：默认路径的 dir 可能是 $HOME，
	// 无条件 chmod 会把用户主目录改成 0700。
	if _, statErr := os.Stat(dir); statErr != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(trimmedPath)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.WriteString(trimmedValue + "\n"); err != nil {
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
	if err := os.Rename(tmpPath, trimmedPath); err != nil {
		return err
	}
	committed = true
	syncStateParentDir(dir)
	return nil
}

func syncStateParentDir(dir string) {
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

func generateRandomNodeUUID() (string, error) {
	id, err := newRandomNodeUUID()
	if err != nil {
		return "", fmt.Errorf("generate node uuid: %w", err)
	}
	return id.String(), nil
}
