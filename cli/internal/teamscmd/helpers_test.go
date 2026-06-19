// SPDX-License-Identifier: MIT

package teamscmd

import (
	"os"
	"testing"
)

func writeFileT(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o644)
}
