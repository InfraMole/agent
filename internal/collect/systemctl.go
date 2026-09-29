// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"strings"

	"github.com/InfraMole/agent/internal/protocol"
)

// parseSystemctl parses `systemctl list-units --plain --no-legend` output:
// "UNIT LOAD ACTIVE SUB DESCRIPTION...". Platform-independent for testing.
func parseSystemctl(output string) []protocol.Service {
	out := []protocol.Service{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		out = append(out, protocol.Service{
			Name:        truncate(strings.TrimSuffix(fields[0], ".service"), protocol.MaxShortStringLen),
			DisplayName: truncate(strings.Join(fields[4:], " "), protocol.MaxShortStringLen),
			State:       truncate(fields[3], 32),
		})
		if len(out) >= protocol.MaxServices {
			break
		}
	}
	return out
}
