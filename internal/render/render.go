// SPDX-License-Identifier: MIT

package render

import "fmt"

type Renderer struct {
	format string
}

func New(format string) Renderer {
	return Renderer{format: format}
}

func (r Renderer) Render(payload string) (string, error) {
	switch r.format {
	case "text", "markdown":
		return payload, nil
	case "json":
		return fmt.Sprintf("{\"message\":%q}", payload), nil
	default:
		return "", fmt.Errorf("unsupported renderer format %q", r.format)
	}
}
