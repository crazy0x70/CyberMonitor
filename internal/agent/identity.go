package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultNodeIDFileName     = ".cybermonitor-node-id"
	defaultAgentTokenFileName = ".cybermonitor-agent-token"
)

type nodeRegisterResponse struct {
	NodeID     string `json:"node_id"`
	AgentToken string `json:"agent_token"`
}

func ResolveStateFilePath(explicit, fallbackName string) (string, error) {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed, nil
	}
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(resolved), fallbackName), nil
}

func ResolveOrCreateNodeID(explicit, filePath string) (string, error) {
	return resolveOrCreateNodeID(explicit, filePath, generateRandomNodeID)
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

func resolveOrCreateNodeID(explicit, filePath string, generate func() string) (string, error) {
	if value := strings.TrimSpace(explicit); value != "" {
		return value, nil
	}
	if value, err := readTrimmedFile(filePath); err == nil && value != "" {
		return value, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	nodeID := strings.TrimSpace(generate())
	if nodeID == "" {
		return "", fmt.Errorf("generated node id is empty")
	}
	if err := writeTrimmedFile(filePath, nodeID); err != nil {
		return "", err
	}
	return nodeID, nil
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
	return strings.TrimSpace(string(data)), nil
}

func writeTrimmedFile(filePath, value string) error {
	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return fmt.Errorf("file path required")
	}
	if err := os.MkdirAll(filepath.Dir(trimmedPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(trimmedPath, []byte(strings.TrimSpace(value)+"\n"), 0o600)
}

func generateRandomNodeID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "node-fallback"
	}
	return "node-" + hex.EncodeToString(buf)
}
