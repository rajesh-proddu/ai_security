package detect

// V1 is the fast detector set of DESIGN §3.3: everything except injection_ml,
// which is a Python sidecar with its own latency budget (Phase 2).
//
// customDict is supplied by the caller because a tenant dictionary has nowhere
// to live in the DESIGN §3.6 policy yet; passing nil registers an empty one, so
// the wiring exists and matches nothing.
func V1(customDict *CustomDict, allowedDomains []string) (*Registry, error) {
	if customDict == nil {
		empty, err := NewCustomDict(nil, nil)
		if err != nil {
			return nil, err
		}
		customDict = empty
	}
	return NewRegistry(
		PII{},
		Secrets{},
		customDict,
		InjectionHeuristic{},
		NewExfilURL(allowedDomains),
	)
}
