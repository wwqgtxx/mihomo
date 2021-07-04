package rules

import (
	"errors"
	"net"
	"testing"

	"github.com/Dreamacro/clash/constant"

	"github.com/stretchr/testify/assert"
)

func TestIpv4AddSuccess(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	err := tree.Insert("10.0.0.2/16")
	assert.Equal(t, nil, err)
}

func TestIpv4AddFail(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	err := tree.Insert("333.00.23.2/23")
	assert.IsType(t, errors.New(""), err)

	err = tree.Insert("22.3.34.2/222")
	assert.IsType(t, errors.New(""), err)

	err = tree.Insert("2.2.2.2")
	assert.IsType(t, nil, err)
}

func match(tree *IpCidrTree, ip string) bool {
	return tree.Match(&constant.Metadata{DstIP: net.ParseIP(ip)})
}

func TestIpv4Match(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	assert.NoError(t, tree.Insert("129.2.36.0/16"))
	assert.NoError(t, tree.Insert("10.2.36.0/18"))
	assert.NoError(t, tree.Insert("16.2.23.0/24"))
	assert.NoError(t, tree.Insert("11.2.13.2/26"))
	assert.NoError(t, tree.Insert("55.5.6.3/8"))
	assert.NoError(t, tree.Insert("66.23.25.4/6"))
	assert.Equal(t, true, match(tree, "129.2.3.65"))
	assert.Equal(t, false, match(tree, "15.2.3.1"))
	assert.Equal(t, true, match(tree, "11.2.13.1"))
	assert.Equal(t, true, match(tree, "55.0.0.0"))
	assert.Equal(t, true, match(tree, "64.0.0.0"))
	assert.Equal(t, false, match(tree, "128.0.0.0"))

	assert.Equal(t, false, match(tree, "22"))
	assert.Equal(t, false, match(tree, ""))
}

func TestIpv4Match2(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	assert.NoError(t, tree.Insert("172.16.0.0/12"))
	assert.Equal(t, false, match(tree, "172.67.69.158"))
	assert.Equal(t, true, match(tree, "172.31.255.255"))
}

func TestIpv6AddSuccess(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	err := tree.Insert("2001:0db8:02de:0000:0000:0000:0000:0e13/32")
	assert.Equal(t, nil, err)

	err = tree.Insert("2001:1db8:f2de::0e13/18")
	assert.Equal(t, nil, err)
}

func TestIpv6AddFail(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	err := tree.Insert("2001::25de::cade/23")
	assert.IsType(t, errors.New(""), err)

	err = tree.Insert("2001:0fa3:25de::cade/222")
	assert.IsType(t, errors.New(""), err)

	err = tree.Insert("2001:0fa3:25de::cade")
	assert.IsType(t, nil, err)
}

func TestIpv6Match(t *testing.T) {
	tree := newEmptyIPCIDRTrie()
	assert.NoError(t, tree.Insert("2001:b28:f23d:f001::e/128"))
	assert.NoError(t, tree.Insert("2001:67c:4e8:f002::e/12"))
	assert.NoError(t, tree.Insert("2001:b28:f23d:f003::e/96"))
	assert.NoError(t, tree.Insert("2001:67c:4e8:f002::a/32"))
	assert.NoError(t, tree.Insert("2001:67c:4e8:f004::a/60"))
	assert.NoError(t, tree.Insert("2001:b28:f23f:f005::a/64"))
	assert.Equal(t, true, match(tree, "2001:b28:f23d:f001::e"))
	assert.Equal(t, false, match(tree, "2222::fff2"))
	assert.Equal(t, true, match(tree, "2000::ffa0"))
	assert.Equal(t, true, match(tree, "2001:b28:f23f:f005:5662::"))
	assert.Equal(t, true, match(tree, "2001:67c:4e8:9666::1213"))

	assert.Equal(t, false, match(tree, "22233:22"))
}
