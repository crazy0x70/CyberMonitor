package agentrpc

import "cyber_monitor/internal/metrics"

type RegisterRequest struct {
	NodeID         string
	BootstrapToken string
}

type RegisterResponse struct {
	NodeID     string
	AgentToken string
}

type ConfigRequest struct {
	NodeID       string
	AgentToken   string
	Capabilities []string
}

type UpdateInstruction struct {
	ID          string
	Version     string
	DownloadURL string
	ChecksumURL string
	RequestedAt int64
}

type ConfigResponse struct {
	Alias           string
	Group           string
	AgentToken      string
	Tests           []metrics.NetworkTestConfig
	TestIntervalSec int
	Update          *UpdateInstruction
}

type ReportStatsRequest struct {
	AgentToken string
	Stats      metrics.NodeStats
}

type ReportStatsResponse struct {
	Status        string
	RefreshConfig bool
}

type ReportUpdateRequest struct {
	NodeID     string
	AgentToken string
	UpdateID   string
	State      string
	Version    string
	Message    string
}

type ReportUpdateResponse struct {
	Status string
}
