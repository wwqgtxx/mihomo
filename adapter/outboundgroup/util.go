package outboundgroup

type SelectAble interface {
	Set(string) error
	ForceSet(name string)
}

var _ SelectAble = (*Selector)(nil)
