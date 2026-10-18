package s3proxy

import (
	"net/http"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/store"
)

// TestLoadHEAD checks NFR-PERF-1 and NFR-PERF-2: 1,000 concurrent HEADs all
// succeed, pass-through adds at most 10 ms p95 over the backend, and cache
// hits take at most 5 ms p95. Timing depends on the machine, so it only runs
// with YPROXY_LOAD_TEST=1 (CI runs it without the race detector).
func TestLoadHEAD(t *testing.T) {
	if os.Getenv("YPROXY_LOAD_TEST") == "" {
		t.Skip("set YPROXY_LOAD_TEST=1 to run the load test")
	}
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 2000, MaxIdleConnsPerHost: 2000}}

	pass := newEnv(t, &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"ab/cd/obj": sstateObj}})
	passTok, _ := pass.token(store.Scope{Buckets: []string{"*"}}, time.Hour)
	passURL := pass.proxy.URL + "/t/" + passTok + "/sstate/ab/cd/obj"
	backendURL := pass.handler.backends["sstate"].(*s3Backend).client.Options().BaseEndpoint

	ce := newCacheEnv(t, map[string][]byte{"ab/cd/obj": sstateObj})
	ce.get("GET", "imm", "ab/cd/obj", nil)
	ce.waitCached("imm", "ab/cd/obj")
	hitURL := ce.proxy.URL + "/t/" + ce.tok + "/imm/ab/cd/obj"

	// NFR-PERF-2: 1,000 at once, pass-through and cache hits.
	for name, url := range map[string]string{"pass-through": passURL, "cache hit": hitURL} {
		lat, failed := run(client, url, 1000, 1000)
		if failed > 0 {
			t.Errorf("%s: %d of 1000 concurrent HEADs failed", name, failed)
		}
		t.Logf("%s, 1000 concurrent: p50 %v, p95 %v, max %v", name, pct(lat, 50), pct(lat, 95), lat[len(lat)-1])
	}

	// NFR-PERF-1: latency at a moderate concurrency, warm connections.
	direct, _ := run(client, *backendURL+"/yocto-sstate/ab/cd/obj", 16, 2000)
	viaProxy, _ := run(client, passURL, 16, 2000)
	hits, _ := run(client, hitURL, 16, 2000)
	overhead := pct(viaProxy, 95) - pct(direct, 95)
	t.Logf("backend p95 %v, pass-through p95 %v (adds %v), cache hit p95 %v",
		pct(direct, 95), pct(viaProxy, 95), overhead, pct(hits, 95))
	if overhead > 10*time.Millisecond {
		t.Errorf("pass-through HEAD adds %v p95, want <= 10ms", overhead)
	}
	if p := pct(hits, 95); p > 5*time.Millisecond {
		t.Errorf("cache-hit HEAD p95 is %v, want <= 5ms", p)
	}
}

// run sends n HEADs to url with the given concurrency and returns the sorted
// latencies of successful requests and the number of failures.
func run(c *http.Client, url string, concurrency, n int) ([]time.Duration, int) {
	var (
		mu     sync.Mutex
		lat    = make([]time.Duration, 0, n)
		failed int
		wg     sync.WaitGroup
		jobs   = make(chan struct{})
	)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				start := time.Now()
				resp, err := c.Head(url)
				d := time.Since(start)
				ok := err == nil && resp.StatusCode == http.StatusOK
				if resp != nil {
					resp.Body.Close()
				}
				mu.Lock()
				if ok {
					lat = append(lat, d)
				} else {
					failed++
				}
				mu.Unlock()
			}
		}()
	}
	for range n {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if len(lat) == 0 {
		lat = append(lat, 0)
	}
	return lat, failed
}

func pct(sorted []time.Duration, p int) time.Duration { return sorted[(len(sorted)-1)*p/100] }
