// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

func TestWorkloadsWaitForTheServer(t *testing.T) {
	w := &serverWorkloads{} // no collector on this platform is fine: nil-safe
	if got := w.due(context.Background(), time.Now()); got != nil {
		t.Fatalf("sent workloads before the server accepted them: %+v", got)
	}
	var nilW *serverWorkloads
	if nilW.due(context.Background(), time.Now()) != nil {
		t.Fatal("nil receiver must be a no-op")
	}
	if !hasFeature([]string{"x", protocol.FeatureWorkloads}, protocol.FeatureWorkloads) || hasFeature(nil, protocol.FeatureWorkloads) {
		t.Fatal("hasFeature")
	}
}
