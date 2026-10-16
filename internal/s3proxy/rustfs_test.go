package s3proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// TestRustFS runs against a real S3-compatible server. It's skipped unless
// RUSTFS_ENDPOINT, RUSTFS_ACCESS_KEY and RUSTFS_SECRET_KEY are set, e.g.:
//
//	docker run -d -p 9000:9000 -e RUSTFS_ACCESS_KEY=... -e RUSTFS_SECRET_KEY=... rustfs/rustfs
func TestRustFS(t *testing.T) {
	endpoint, ak, sk := os.Getenv("RUSTFS_ENDPOINT"), os.Getenv("RUSTFS_ACCESS_KEY"), os.Getenv("RUSTFS_SECRET_KEY")
	if endpoint == "" {
		t.Skip("RUSTFS_ENDPOINT not set")
	}
	ctx := context.Background()
	bucket := fmt.Sprintf("it-%d", time.Now().UnixNano())

	admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(ak, sk, "")})
	if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	obj := bytes.Repeat([]byte("0123456789"), 100_000) // 1 MB
	key := "ab/cd/sstate:quilt-native:x86_64-linux:0.67:r0:x86_64:11:abcdef_populate_sysroot.tar.zst"
	if _, err := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(obj)}); err != nil {
		t.Fatalf("put object: %v", err)
	}

	dir := t.TempDir()
	akf, skf := filepath.Join(dir, "ak"), filepath.Join(dir, "sk")
	os.WriteFile(akf, []byte(ak), 0o600)
	os.WriteFile(skf, []byte(sk), 0o600)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
buckets:
  - alias: sstate
    provider: rustfs
    endpoint: %s
    bucket: %s
    credentials: { access_key_id: { file: %s }, secret_access_key: { file: %s } }
  - alias: wrongcreds
    provider: rustfs
    endpoint: %s
    bucket: %s
    credentials: { access_key_id: { file: %s }, secret_access_key: { file: %s } }
`, endpoint, bucket, akf, skf, endpoint, bucket, akf, akf)), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(ctx, filepath.Join(dir, "p.db"))
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authn := auth.New(st, log, "", time.Second)
	backends := map[string]Backend{}
	for _, b := range cfg.Buckets {
		backends[b.Alias] = NewS3Backend(b)
	}
	h := NewHandler(backends, authn, log, prometheus.NewRegistry(), false)
	srv := httptest.NewServer(h)
	defer srv.Close()

	tokVal := auth.NewSecret(auth.TokenPrefix)
	st.CreateToken(ctx, &store.Token{ID: "tok_it", Hash: auth.Hash(tokVal), Kind: "ci",
		Scope: store.Scope{Buckets: []string{"*"}}, CreatedBy: "it", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	get := func(method, path string, hdr ...string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, srv.URL+"/t/"+tokVal+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	if resp, b := get("GET", "/sstate/"+key); resp.StatusCode != 200 || !bytes.Equal(b, obj) {
		t.Fatalf("GET = %d, %d bytes", resp.StatusCode, len(b))
	}
	if resp, _ := get("HEAD", "/sstate/"+key); resp.StatusCode != 200 || resp.ContentLength != int64(len(obj)) {
		t.Fatalf("HEAD = %d, length %d", resp.StatusCode, resp.ContentLength)
	}
	if resp, _ := get("HEAD", "/sstate/ab/cd/missing.tar.zst"); resp.StatusCode != 404 {
		t.Fatalf("missing HEAD = %d, want 404", resp.StatusCode)
	}
	if resp, _ := get("GET", "/sstate/ab/cd/missing.tar.zst"); resp.StatusCode != 404 {
		t.Fatalf("missing GET = %d, want 404", resp.StatusCode)
	}
	if resp, b := get("GET", "/sstate/"+key, "Range", "bytes=10-19"); resp.StatusCode != 206 || string(b) != "0123456789" {
		t.Fatalf("Range = %d %q", resp.StatusCode, b)
	}
	resp, _ := get("HEAD", "/sstate/"+key)
	if r2, _ := get("GET", "/sstate/"+key, "If-None-Match", resp.Header.Get("ETag")); r2.StatusCode != 304 {
		t.Fatalf("If-None-Match = %d, want 304", r2.StatusCode)
	}
	if resp, _ := get("GET", "/wrongcreds/"+key); resp.StatusCode != 502 {
		t.Fatalf("wrong credentials = %d, want 502", resp.StatusCode)
	}
	if err := backends["sstate"].Test(ctx); err != nil {
		t.Fatalf("bucket test: %v", err)
	}
	if err := backends["wrongcreds"].Test(ctx); err == nil {
		t.Fatal("bucket test with wrong credentials passed")
	}
}
