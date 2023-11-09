package rules

import (
	C "github.com/metacubex/mihomo/constant"

	"github.com/kentik/patricia"
	tree "github.com/kentik/patricia/generics_tree"
)

type IpCidrTree struct {
	IPCIDR    // for C.Rule interface
	treeV4    *tree.TreeV4[struct{}]
	treeV6    *tree.TreeV6[struct{}]
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
	found := false
	if ip.Is4() {
		v4 := patricia.NewIPv4AddressFromBytes(ip.AsSlice(), 32)
		found, _ = i.treeV4.FindDeepestTag(v4)
	} else {
		v6 := patricia.NewIPv6Address(ip.AsSlice(), 128)
		found, _ = i.treeV6.FindDeepestTag(v6)
	}
	return found, i.adapter
}

func (i *IpCidrTree) Insert(ipCidr string) error {
	v4, v6, err := patricia.ParseIPFromString(ipCidr)
	if err != nil {
		return err
	}
	if v4 != nil {
		_, _ = i.treeV4.Set(*v4, struct{}{})
	} else {
		_, _ = i.treeV6.Set(*v6, struct{}{})
	}
	i.ruleCount++
	return nil
}

func (i *IpCidrTree) FinishInsert() {}

func NewIPCIDRTree() *IpCidrTree {
	return &IpCidrTree{
		IPCIDR:    IPCIDR{},
		treeV4:    tree.NewTreeV4[struct{}](),
		treeV6:    tree.NewTreeV6[struct{}](),
		ruleCount: 0,
	}
}
