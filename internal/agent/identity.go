package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	LegacyPath   string
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

func ResolveNodeID(opts NodeIDOptions) (string, error) {
	return resolveNodeIDWithFallbacks(opts)
}

func ResolveOrCreateNodeID(explicit, filePath string) (string, error) {
	return ResolveOrCreateNodeIDWithOptions(NodeIDOptions{
		Explicit:     explicit,
		ExplicitFile: filePath,
	})
}

func ResolveOrCreateNodeIDWithOptions(opts NodeIDOptions) (string, error) {
	nodeID, err := ResolveNodeID(opts)
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

func LoadPersistedAgentToken(filePath string) (string, error) {
	return loadPersistedAgentToken(filePath)
}

func PersistAgentToken(filePath, token string) error {
	return persistAgentToken(filePath, token)
}

func RegisterNodeToken(ctx context.Context, client *http.Client, endpoint, nodeID, bootstrapToken string) (string, error) {
	return registerNodeToken(ctx, client, endpoint, nodeID, bootstrapToken)
}

func DefaultNodeIDFileName() string {
	return defaultNodeIDFileName
}

func DefaultAgentTokenFileName() string {
	return defaultAgentTokenFileName
}

func resolveNodeIDWithFallbacks(opts NodeIDOptions) (string, error) {
	if explicit := strings.TrimSpace(opts.Explicit); explicit != "" {
		return explicit, nil
	}

	if explicitFile := strings.TrimSpace(opts.ExplicitFile); explicitFile != "" {
		value, err := readTrimmedFile(explicitFile)
		switch {
		case err == nil:
			return value, nil
		case !errors.Is(err, os.ErrNotExist):
			return "", err
		}
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

	legacyPath := strings.TrimSpace(opts.LegacyPath)
	if legacyPath != "" {
		value, err := readTrimmedFile(legacyPath)
		switch {
		case err == nil:
			if homeErr != nil {
				return "", homeErr
			}
			if err := writeTrimmedFile(homePath, value); err != nil {
				return "", err
			}
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
	if explicitFile := strings.TrimSpace(opts.ExplicitFile); explicitFile != "" {
		return explicitFile, nil
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
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			return "", fmt.Errorf("register status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("register status %d: %s", resp.StatusCode, message)
	}
	var payload nodeRegisterResponse
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("register response has trailing data")
		}
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
