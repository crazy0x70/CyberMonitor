//go:build !windows

package main

import "cyber_monitor/internal/agent"

func maybeRunAsService(cfg agent.Config) (bool, error) {
	return false, nil
}
