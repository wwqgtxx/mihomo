package rules

import (
	"github.com/metacubex/mihomo/component/cidr"
	C "github.com/metacubex/mihomo/constant"
)

type IpCidrTree struct {
	IPCIDR    // for C.Rule interface
	cidrSet   *cidr.IpCidrSet
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
	if i.cidrSet.IsContain(ip) {
		return true, i.adapter
	}
	return false, ""
}

func (i *IpCidrTree) Insert(ipCidr string) error {
	err := i.cidrSet.AddIpCidrForString(ipCidr)
	if err != nil {
		return err
	}
	i.ruleCount++
	return nil
}

func (i *IpCidrTree) FinishInsert() error {
	return i.cidrSet.Merge()
}

func NewIPCIDRTree() *IpCidrTree {
	return &IpCidrTree{
		IPCIDR:    IPCIDR{},
		cidrSet:   cidr.NewIpCidrSet(),
		ruleCount: 0,
	}
}
