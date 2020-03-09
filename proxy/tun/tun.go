package tun

// TunAdapter hold the state of tun/tap interface
type TunAdapter interface {
	Close()
	DeviceURL() string
}
