//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The fast-path target (DESIGN §2, ROADMAP Phase 1): p99 ≤ 20 ms added by
// ai_security, including the gateway→inspector hop.
const fastPathP99 = 20 * time.Millisecond

var (
	metricsURL = env("E2E_GATEWAY_METRICS", "http://localhost:15020/metrics")
	inspector  = env("E2E_INSPECTOR_GRPC", "localhost:9000")
)

// guardrailBuckets reads the gateway's own histogram of calls to the
// inspector: cumulative counts by upper bound in seconds.
func guardrailBuckets(t *testing.T) map[float64]float64 {
	t.Helper()
	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[float64]float64{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "agentgateway_upstream_call_duration_seconds_bucket{") ||
			!strings.Contains(line, `kind="Policy",subtype="Guardrail"`) {
			continue
		}
		le := line[strings.Index(line, `le="`)+4:]
		le = le[:strings.Index(le, `"`)]
		bound := math.Inf(1)
		if le != "+Inf" {
			bound, _ = strconv.ParseFloat(le, 64)
		}
		count, _ := strconv.ParseFloat(line[strings.LastIndex(line, " ")+1:], 64)
		out[bound] = count
	}
	return out
}

// p99Bound returns the smallest histogram bound that holds at least 99% of the
// calls made between two readings.
func p99Bound(before, after map[float64]float64) (time.Duration, float64) {
	bounds := make([]float64, 0, len(after))
	for b := range after {
		bounds = append(bounds, b)
	}
	sort.Float64s(bounds)
	total := after[math.Inf(1)] - before[math.Inf(1)]
	for _, b := range bounds {
		if (after[b]-before[b])/total >= 0.99 {
			return time.Duration(b * float64(time.Second)), total
		}
	}
	return time.Duration(math.MaxInt64), total
}

func percentile(ds []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(math.Ceil(p*float64(len(s))))-1]
}

func TestFastPathLatency(t *testing.T) {
	const n = 300

	// 1. MCP hook, measured by the gateway itself: each tools/call is two
	// ExtMcp calls (params, then result), each hop included.
	t.Run("mcp via gateway", func(t *testing.T) {
		c := newMCP(t, session(t))
		for range 20 { // warm up
			c.tool("get_customer", map[string]any{"customer_id": "warm"})
		}
		before := guardrailBuckets(t)
		for i := range n {
			c.tool("get_customer", map[string]any{"customer_id": strconv.Itoa(i)})
		}
		bound, calls := p99Bound(before, guardrailBuckets(t))
		t.Logf("gateway-measured guardrail calls: %.0f, p99 ≤ %v (histogram bound)", calls, bound)
		if bound > fastPathP99 {
			t.Errorf("p99 bound %v exceeds %v (bounds are 1, 5, 10, 25 ms; 25 ms is inconclusive)", bound, fastPathP99)
		}
	})

	// 2. LLM hook: a whole ext_proc exchange against the inspector, from the
	// host. Through the gateway the call would also wait on the model.
	t.Run("ext_proc direct", func(t *testing.T) {
		conn, err := grpc.NewClient(inspector, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := extproc.NewExternalProcessorClient(conn)
		sess := session(t)
		body := `{"model":"chat-default","messages":[{"role":"system","content":"You recommend videos."},` +
			`{"role":"user","content":"` + strings.Repeat("Suggest a cooking video like the last one. ", 40) + `"}]}`
		resp := `{"choices":[{"message":{"role":"assistant","content":"` + strings.Repeat("Try the biryani class. ", 30) + `"}}]}`
		exchange := func() time.Duration {
			start := time.Now()
			s, err := client.Process(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			hdr := func(kv ...string) *corev3.HeaderMap {
				hm := &corev3.HeaderMap{}
				for i := 0; i < len(kv); i += 2 {
					hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
				}
				return hm
			}
			for _, m := range []*extproc.ProcessingRequest{
				{Request: &extproc.ProcessingRequest_RequestHeaders{RequestHeaders: &extproc.HttpHeaders{Headers: hdr(":path", "/v1/chat/completions", "x-session-id", sess)}}},
				{Request: &extproc.ProcessingRequest_RequestBody{RequestBody: &extproc.HttpBody{Body: []byte(body), EndOfStream: true}}},
				{Request: &extproc.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extproc.HttpHeaders{Headers: hdr(":status", "200", "content-type", "application/json")}}},
				{Request: &extproc.ProcessingRequest_ResponseBody{ResponseBody: &extproc.HttpBody{Body: []byte(resp), EndOfStream: true}}},
			} {
				if err := s.Send(m); err != nil {
					t.Fatal(err)
				}
			}
			_ = s.CloseSend()
			for {
				if _, err := s.Recv(); errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
			return time.Since(start)
		}
		for range 20 {
			exchange()
		}
		ds := make([]time.Duration, n)
		for i := range ds {
			ds[i] = exchange()
		}
		// One exchange is two inspections (input and output), so it is
		// compared against twice the per-hop budget.
		p50, p99 := percentile(ds, 0.50), percentile(ds, 0.99)
		t.Logf("ext_proc exchange (input + output inspection, host→container): p50 %v, p99 %v", p50, p99)
		if p99 > 2*fastPathP99 {
			t.Errorf("p99 %v exceeds %v for two inspections", p99, 2*fastPathP99)
		}
	})

	// 3. The inspection alone, as the inspector records it.
	t.Run("audit latency_ms", func(t *testing.T) {
		var ds []time.Duration
		for _, e := range inspectorAudit(t) {
			ds = append(ds, time.Duration(e.LatencyMS*float64(time.Millisecond)))
		}
		if len(ds) < 100 {
			t.Skipf("only %d audit events", len(ds))
		}
		t.Logf("inspection time over %d audit events: p50 %v, p99 %v", len(ds), percentile(ds, 0.50), percentile(ds, 0.99))
	})
}
