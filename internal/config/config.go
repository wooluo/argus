// Package config: 环境变量 + 默认值（对齐原 config.py 语义）。
package config

import (
	"os"
	"strconv"
)

type Config struct {
	ListenAddr string // ARGUS_ADDR，默认 :7887
	DataDir    string // ARGUS_DATA，默认 ./data
	Token      string // ARGUS_TOKEN，空=本地模式（不鉴权，与原项目一致）
	DBPath     string
	StaticDir  string // ARGUS_STATIC，空=使用内嵌 UI
}

func Load() *Config {
	c := &Config{
		ListenAddr: getenv("ARGUS_ADDR", ":7887"),
		DataDir:    getenv("ARGUS_DATA", "./data"),
		Token:      os.Getenv("ARGUS_TOKEN"),
		StaticDir:  os.Getenv("ARGUS_STATIC"),
	}
	c.DBPath = c.DataDir + "/argus.db"
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
