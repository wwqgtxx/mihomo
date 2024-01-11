package rules

import (
	C "github.com/metacubex/mihomo/constant"
	"go4.org/netipx"
	"net/netip"
)

type IpCidrTree struct {
	IPCIDR    // for C.Rule interface
	ipSet     *netipx.IPSet
	ruleCount int
}

func (i *IpCidrTree) RuleCount() int {
	return i.ruleCount
}

func (i *IpCidrTree) RuleType() C.RuleType {
	return C.IpCidrTree
}

func (i *IpCidrTree) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if i.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}
	if i.ipSet == nil {
		return false, ""
	}
	if i.ipSet.Contains(ip) {
		return true, i.adapter
	}
	return false, ""
}

func (i *IpCidrTree) Insert(ipCidr string) error {
	prefix, err := netip.ParsePrefix(ipCidr)
	if err != nil {
		return err
	}
	var b netipx.IPSetBuilder
	b.AddSet(i.ipSet)
	b.AddPrefix(prefix)
	i.ipSet, err = b.IPSet()
	if err != nil {
		return err
	}
	i.ruleCount++
	return nil
}

func (i *IpCidrTree) FinishInsert() {}

func NewIPCIDRTree() *IpCidrTree {
	return &IpCidrTree{
		IPCIDR:    IPCIDR{},
		ruleCount: 0,
	}
}
