package constant

import (
	"os"
	P "path"
	"path/filepath"
)

const Name = "clash"

// Path is used to get the configuration path
//
// on Unix systems, `$HOME/.config/clash`.
// on Windows, `%USERPROFILE%/.config/clash`.
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}

	homeDir = P.Join(homeDir, ".config", Name)

	if _, err = os.Stat(homeDir); err != nil {
		if configHome, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
			homeDir = P.Join(configHome, Name)
		}
	}
	return &path{homeDir: homeDir, configFile: "config.yaml"}
}()

type path struct {
	homeDir    string
	configFile string
	extraMMDB  bool
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func SetExtraMMDB(extraMMDB bool) {
	Path.extraMMDB = extraMMDB
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}

	return path
}

func (p *path) MMDB() string {
	if p.extraMMDB {
		return P.Join(p.homeDir, "Country.mmdb")
	} else {
		return "embed"
	}
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}

func (p *path) CachePlain() string {
	return P.Join(p.homeDir, "cache.json")
}
