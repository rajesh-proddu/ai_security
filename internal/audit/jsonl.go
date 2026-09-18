package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
)

// JSONLSink writes one JSON object per line. The local sink of DESIGN §3.8;
// Kafka and OTLP sinks are later phases.
type JSONLSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLSink writes to w. Closing w is the caller's business.
func NewJSONLSink(w io.Writer) *JSONLSink {
	return &JSONLSink{enc: json.NewEncoder(w)}
}

func (s *JSONLSink) Write(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(e)
}
