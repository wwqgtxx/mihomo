package rules

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"strings"
)

type InUser struct {
	users   []string
	adapter string
	payload string
}

func (u *InUser) Match(metadata *C.Metadata) (bool, string) {
	for _, user := range u.users {
		if metadata.InUser == user {
			return true, u.adapter
		}
	}
	return false, ""
}

func (u *InUser) RuleType() C.RuleType {
	return C.InUser
}

func (u *InUser) Adapter() string {
	return u.adapter
}

func (u *InUser) Payload() string {
	return u.payload
}

func (u *InUser) ShouldResolveIP() bool {
	return false
}

func (u *InUser) ShouldFindProcess() bool {
	return false
}

func NewInUser(iUsers, adapter string) (*InUser, error) {
	users := strings.Split(iUsers, "/")
	if len(users) == 0 {
		return nil, fmt.Errorf("in user couldn't be empty")
	}

	return &InUser{
		users:   users,
		adapter: adapter,
		payload: iUsers,
	}, nil
}
