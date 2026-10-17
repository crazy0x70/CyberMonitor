//go:build !linux

package metrics

import gnet "github.com/shirou/gopsutil/v4/net"

func readConnectionCounts() (int, int) {
	tcpConns := 0
	udpConns := 0
	if conns, err := gnet.Connections("tcp"); err == nil {
		tcpConns = len(conns)
	}
	if conns, err := gnet.Connections("udp"); err == nil {
		udpConns = len(conns)
	}
	return tcpConns, udpConns
}
