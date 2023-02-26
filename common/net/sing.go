package net

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/network"
)

func NeedHandshake(conn any) bool {
	if earlyConn, isEarlyConn := common.Cast[network.EarlyConn](conn); isEarlyConn && earlyConn.NeedHandshake() {
		return true
	}
	return false
}
