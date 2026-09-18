package detect

import (
	"context"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Noop finds nothing. It exists so the registry and the pipeline can be wired
// and exercised before the v1 detectors of DESIGN §3.3 land in Phase 1.
type Noop struct{}

func (Noop) Name() string { return "noop" }

func (Noop) Detect(context.Context, core.Request) ([]core.Finding, error) { return nil, nil }

var _ Detector = Noop{}
