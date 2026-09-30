// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package inventory

import (
	"fmt"
	"os"
)

// checkPrivate refuses a credential file readable by group or others.
func checkPrivate(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group/others (run: chmod 600 %s)", path, path)
	}
	return nil
}
