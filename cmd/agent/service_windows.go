//go:build windows

package main

import (
	"context"
	"errors"
	"log"

	"cyber_monitor/internal/agent"
	"golang.org/x/sys/windows/svc"
)

type agentService struct {
	cfg agent.Config
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Run(ctx, s.cfg)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("Agent 运行失败: %v", err)
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			case svc.Interrogate:
				status <- req.CurrentStatus
			}
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("Agent 运行失败: %v", err)
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

func maybeRunAsService(cfg agent.Config) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	return true, svc.Run("CyberMonitorAgent", &agentService{cfg: cfg})
}
