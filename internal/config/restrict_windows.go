// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package config

import "golang.org/x/sys/windows"

// restrict replaces the DACL with: SYSTEM, Administrators and the owner
// (full control), no inheritance from the parent.
func restrict(path string, isDir bool) error {
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
	if isDir {
		sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
