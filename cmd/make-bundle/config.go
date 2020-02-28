package main

import (
	"github.com/spf13/viper"
)

func configDefaults() {
	viper.SetDefault("ca.path", ".")
}
