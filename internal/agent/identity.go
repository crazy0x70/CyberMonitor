package agent

import (
	"context"
	"errors"
	"fmt"
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
	homePath, err := defaultAgentTokenHomePath()
	if err != nil {
		return "", err
	}
	if err := migrateLegacyStateFile(homePath, defaultAgentTokenFileName); err != nil {
		return "", err
	}
	return homePath, nil
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

func defaultLegacyStateFilePath(fileName string) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(resolved), fileName), nil
}

func migrateLegacyStateFile(targetPath, fileName string) error {
	if strings.TrimSpace(targetPath) == "" {
		return fmt.Errorf("target path required")
	}
	if _, err := os.Stat(targetPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	legacyPath, err := defaultLegacyStateFilePath(fileName)
	if err != nil {
		return nil
	}
	if legacyPath == targetPath {
		return nil
	}

	value, err := readTrimmedFile(legacyPath)
	switch {
	case err == nil:
		return writeTrimmedFile(targetPath, value)
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return err
	}
}

func ResolveOrCreateNodeIDWithOptions(opts NodeIDOptions) (string, error) {
	opts = normalizeNodeIDOptions(opts)
	if err := migrateDefaultNodeIDIfNeeded(opts); err != nil {
		return "", err
	}
	nodeID, err := resolveNodeIDWithFallbacks(opts)
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

func migrateDefaultNodeIDIfNeeded(opts NodeIDOptions) error {
	if opts.Explicit != "" || opts.ExplicitFile != "" {
		return nil
	}
	homePath, err := defaultNodeIDHomePath()
	if err != nil {
		return err
	}
	return migrateLegacyStateFile(homePath, defaultNodeIDFileName)
}

func resolveNodeIDWithFallbacks(opts NodeIDOptions) (string, error) {
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
		case !errors.Is(err, os.ErrNotExist):
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

	parts := make([]string, 0, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		value, err := readTrimmedFile(source.path)
		if err != nil {
			continue
		}
		part := source.label + "=" + value
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", os.ErrNotExist
	}
	return strings.Join(parts, "\n"), nil
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
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(endpoint, "/")+"?node_id="+url.QueryEscape(nodeID),
		nil,
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-AGENT-TOKEN", bootstrapToken)
	var payload nodeRegisterResponse
	if err := performAgentJSONRequest(client, req, "register", "register response has trailing data", &payload); err != nil {
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
		return "", os.ErrNotExist
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
	if err := os.MkdirAll(filepath.Dir(trimmedPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(trimmedPath, []byte(trimmedValue+"\n"), 0o600)
}

func generateRandomNodeUUID() (string, error) {
	id, err := newRandomNodeUUID()
	if err != nil {
		return "", fmt.Errorf("generate node uuid: %w", err)
	}
	return id.String(), nil
}
