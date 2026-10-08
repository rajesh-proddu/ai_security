package agentgateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/rajesh-proddu/ai_security/internal/audit"
	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
	"github.com/rajesh-proddu/ai_security/internal/normalize"
	"github.com/rajesh-proddu/ai_security/internal/policy"
	"github.com/rajesh-proddu/ai_security/internal/session"
)

// fixtureMsg is one line of a spike capture: a gRPC message agentgateway sent
// ("in") or the spike server's reply ("out"). Tests replay only "in"; the "out"
// lines are what the throwaway spike server answered, not expected output.
type fixtureMsg struct {
	Svc    string          `json:"svc"`
	Stream int             `json:"stream"`
	Dir    string          `json:"dir"`
	Type   string          `json:"type"`
	Msg    json.RawMessage `json:"msg"`
}

func loadFixture(t *testing.T, name string) []fixtureMsg {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []fixtureMsg
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m fixtureMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m.Dir == "in" {
			out = append(out, m)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// dial serves the adapter over an in-memory listener, so tests go through real
// gRPC framing.
func dial(t *testing.T, in core.Inspector) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(ServerOptions()...)
	Register(srv, in)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(MaxMessageSize), grpc.MaxCallRecvMsgSize(MaxMessageSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// recorder is an Inspector that records requests and answers from a function.
type recorder struct {
	mu      sync.Mutex
	reqs    []core.Request
	verdict func(core.Request) core.Verdict
}

func (r *recorder) Inspect(_ context.Context, req core.Request) (core.Verdict, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	if r.verdict == nil {
		return core.Verdict{Action: core.ActionAllow}, nil
	}
	return r.verdict(req), nil
}

func (r *recorder) requests() []core.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]core.Request(nil), r.reqs...)
}

type discard struct{}

func (discard) Write(context.Context, audit.Event) error { return nil }

// pipeline builds the real inspector: v1 detectors, the normalizer, an
// in-memory session store and the given policy.
func pipeline(t *testing.T, policyYAML string) core.Inspector {
	t.Helper()
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := detect.V1(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := core.NewPipeline(reg, policy.NewEvaluator(pol), session.NewMemory(), discard{}, time.Hour)
	p.Normalizer = normalize.Normalizer{}
	return p
}
