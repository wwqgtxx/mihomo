package cachefileplain

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"

	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	initOnce     sync.Once
	fileMode     os.FileMode = 0666
	defaultCache *CacheFilePlain
)

type cache struct {
	Selected map[string]string
}

// CacheFile store and update the cache file
type CacheFilePlain struct {
	path  string
	model *cache
	buf   *bytes.Buffer
	mux   sync.Mutex
}

func (c *CacheFilePlain) SetSelected(group, selected string) {
	if !profile.StoreSelected.Load() {
		return
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model := c.element()

	model.Selected[group] = selected
	c.buf.Reset()
	if err := json.NewEncoder(c.buf).Encode(model); err != nil {
		log.Warnln("[CacheFile] encode gob failed: %s", err.Error())
		return
	}

	if err := ioutil.WriteFile(c.path, c.buf.Bytes(), fileMode); err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.path, err.Error())
		return
	}
}

func (c *CacheFilePlain) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model := c.element()

	mapping := map[string]string{}
	for k, v := range model.Selected {
		mapping[k] = v
	}
	return mapping
}

func (c *CacheFilePlain) element() *cache {
	if c.model != nil {
		return c.model
	}

	model := &cache{
		Selected: map[string]string{},
	}

	if buf, err := ioutil.ReadFile(c.path); err == nil {
		bufReader := bytes.NewBuffer(buf)
		json.NewDecoder(bufReader).Decode(model)
	}

	c.model = model
	return c.model
}

// CachePlain return singleton of CacheFilePlain
func Cache() *CacheFilePlain {
	initOnce.Do(func() {
		defaultCache = &CacheFilePlain{
			path: C.Path.CachePlain(),
			buf:  &bytes.Buffer{},
		}
	})

	return defaultCache
}
