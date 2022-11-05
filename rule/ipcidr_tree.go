package rules

import (
	C "github.com/Dreamacro/clash/constant"

	"github.com/kentik/patricia"
	tree "github.com/kentik/patricia/generics_tree"
)

type IpCidrTree struct {
	*IPCIDR
	treeV4  *tree.TreeV4[struct{}]
	treeV6  *tree.TreeV6[struct{}]
	insertN int
}

func (i *IpCidrTree) InsertN() int {
	return i.insertN
}

func (i *IpCidrTree) RuleType() C.RuleType {
	return C.IpCidrTree
}

func (i *IpCidrTree) Match(metadata *C.Metadata) bool {
	ip := metadata.DstIP
	if i.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false
	}
	found := false
	if ip.Is4() {
		v4 := patricia.NewIPv4AddressFromBytes(ip.AsSlice(), 32)
		found, _ = i.treeV4.FindDeepestTag(v4)
	} else {
		v6 := patricia.NewIPv6Address(ip.AsSlice(), 128)
		found, _ = i.treeV6.FindDeepestTag(v6)
	}
	return found
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
	i.insertN++
	return nil
}

func newEmptyIPCIDRTrie() *IpCidrTree {
	return &IpCidrTree{
		IPCIDR:  &IPCIDR{},
		treeV4:  tree.NewTreeV4[struct{}](),
		treeV6:  tree.NewTreeV6[struct{}](),
		insertN: 0,
	}
}

func NewIPCIDRTrie(ipCidr string, adapter string, opts ...IPCIDROption) (*IpCidrTree, error) {
	dt := newEmptyIPCIDRTrie()
	i, err := NewIPCIDR(ipCidr, adapter, opts...)
	if err != nil {
		return nil, errPayload
	}
	dt.IPCIDR = i
	err = dt.Insert(ipCidr)

	for _, o := range opts {
		o(dt.IPCIDR)
	}

	return dt, err
}
