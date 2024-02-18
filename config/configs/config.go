package configs

import (
	apiconfig "github.com/goodrain/rainbond/cmd/api/option"
	mqconfig "github.com/goodrain/rainbond/cmd/mq/option"
)

// Env -
type Env string

// Config -
type Config struct {
	AppName   string
	Version   string
	Env       Env
	Debug     bool
	APIConfig apiconfig.Config
	MQConfig  mqconfig.Config
}

var defaultConfig *Config

// Default -
func Default() *Config {
	return defaultConfig
}

// SetDefault -
func SetDefault(cfg *Config) {
	defaultConfig = cfg
}
