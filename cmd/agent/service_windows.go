//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"time"

	"cyber_monitor/internal/agent"
	"golang.org/x/sys/windows/svc"
)

// gracefulStopTimeout 略小于 SCM 默认等待超时，避免强杀跳过 Stopped 上报。
const gracefulStopTimeout = 20 * time.Second

type agentService struct {
	cfg agent.Config
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
				// Run 可能卡在不可中断的系统调用（如 SMB stat）上，无超时
				// 等待会被 SCM 等待超时强杀并跳过 Stopped 状态上报。
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						log.Printf("Agent 运行失败: %v", err)
					}
				case <-time.After(gracefulStopTimeout):
					log.Printf("Agent 未在 %v 内退出，放弃等待", gracefulStopTimeout)
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
