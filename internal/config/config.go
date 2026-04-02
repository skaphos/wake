// SPDX-License-Identifier: MIT

package config

type Config struct {
	ListenNetwork string
	ListenAddress string
}

func Default() Config {
	return Config{
		ListenNetwork: "stdio",
		ListenAddress: "",
	}
}
