package protocol

type Base struct {
	IV       []byte
	Key      []byte
	Overhead int
	Param    string
}
