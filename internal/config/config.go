// SPDX-License-Identifier: MIT

package config

import "fmt"

type Config struct {
	OutputFormat string
	Repository   string
}

func Default() Config {
	return Config{
		OutputFormat: "text",
	}
}

func (c Config) Validate() error {
	switch c.OutputFormat {
	case "text", "json", "markdown":
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", c.OutputFormat)
	}
}
