package history

import (
	"errors"
	"path/filepath"
	"strings"
)

var ErrInvalidNodeID = errors.New("invalid node id")

func NormalizeNodeID(nodeID string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", nil
	}
	if nodeID == "." || nodeID == ".." || filepath.IsAbs(nodeID) || strings.ContainsAny(nodeID, `/\`) {
		return "", ErrInvalidNodeID
	}
	return nodeID, nil
}
