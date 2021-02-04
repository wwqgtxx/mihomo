package tools

import (
	"bytes"
	"sync"
)

var BufPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
