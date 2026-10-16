// Package s3proxy serves objects from S3-compatible buckets to BitBake.
package s3proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/thomaskhub/bucket-cache/internal/config"
)

// Conditions are the client request headers passed through to the backend.
type Conditions struct {
	Range           string
	IfNoneMatch     string
	IfModifiedSince *time.Time
}

// Object is a backend response. Body is nil for HEAD.
type Object struct {
	Body         io.ReadCloser
	Size         int64
	ContentType  string
	ETag         string
	LastModified *time.Time
	ContentRange string
}

// Backend errors, mapped to client status codes in the handler (FR-7).
var (
	ErrNotFound         = errors.New("object not found")
	ErrNotModified      = errors.New("not modified")
	ErrPrecondition     = errors.New("precondition failed")
	ErrRangeUnsatisfied = errors.New("range not satisfiable")
	ErrTimeout          = errors.New("backend timeout")
)

// Backend reads objects from one bucket.
type Backend interface {
	Get(ctx context.Context, key string, c Conditions) (*Object, error)
	Head(ctx context.Context, key string, c Conditions) (*Object, error)
	// Test checks that the bucket is reachable with the configured credentials.
	Test(ctx context.Context) error
}

type s3Backend struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3Backend builds a SigV4 client for one configured bucket, with its own
// connection pool and timeouts so one slow backend can't starve others (FR-41).
func NewS3Backend(b config.Bucket) Backend {
	dialer := &net.Dialer{Timeout: b.Timeouts.Connect.D(), KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       b.Timeouts.Idle.D(),
		TLSHandshakeTimeout:   b.Timeouts.Connect.D(),
		ResponseHeaderTimeout: b.Timeouts.FirstByte.D(),
		ExpectContinueTimeout: time.Second,
	}
	opts := s3.Options{
		Region: b.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			b.Credentials.AccessKeyID.Value(), b.Credentials.SecretAccessKey.Value(), "")),
		UsePathStyle: *b.PathStyle,
		HTTPClient:   &http.Client{Transport: transport},
		// Only validate checksums when the backend requires it: R2 and some
		// self-hosted stores don't support the newer checksum headers.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if b.Endpoint != "" {
		opts.BaseEndpoint = aws.String(b.Endpoint)
	}
	return &s3Backend{client: s3.New(opts), bucket: b.Bucket, prefix: b.Prefix}
}

func (s *s3Backend) Get(ctx context.Context, key string, c Conditions) (*Object, error) {
	in := &s3.GetObjectInput{Bucket: &s.bucket, Key: aws.String(s.prefix + key), IfModifiedSince: c.IfModifiedSince}
	if c.Range != "" {
		in.Range = aws.String(c.Range)
	}
	if c.IfNoneMatch != "" {
		in.IfNoneMatch = aws.String(c.IfNoneMatch)
	}
	out, err := s.client.GetObject(ctx, in)
	if err != nil {
		return nil, mapError(err)
	}
	return &Object{
		Body: out.Body, Size: aws.ToInt64(out.ContentLength), ContentType: aws.ToString(out.ContentType),
		ETag: aws.ToString(out.ETag), LastModified: out.LastModified, ContentRange: aws.ToString(out.ContentRange),
	}, nil
}

func (s *s3Backend) Head(ctx context.Context, key string, c Conditions) (*Object, error) {
	in := &s3.HeadObjectInput{Bucket: &s.bucket, Key: aws.String(s.prefix + key), IfModifiedSince: c.IfModifiedSince}
	if c.IfNoneMatch != "" {
		in.IfNoneMatch = aws.String(c.IfNoneMatch)
	}
	out, err := s.client.HeadObject(ctx, in)
	if err != nil {
		return nil, mapError(err)
	}
	return &Object{
		Size: aws.ToInt64(out.ContentLength), ContentType: aws.ToString(out.ContentType),
		ETag: aws.ToString(out.ETag), LastModified: out.LastModified,
	}, nil
}

func (s *s3Backend) Test(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	return mapError(err)
}

// BackendError is an unexpected backend failure. Its message is safe to log
// but is never sent to clients (it can contain bucket names, FR-7).
type BackendError struct {
	Status int
	Err    error
}

func (e *BackendError) Error() string { return e.Err.Error() }
func (e *BackendError) Unwrap() error { return e.Err }

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		switch re.HTTPStatusCode() {
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusNotModified:
			return ErrNotModified
		case http.StatusPreconditionFailed:
			return ErrPrecondition
		case http.StatusRequestedRangeNotSatisfiable:
			return ErrRangeUnsatisfied
		}
		return &BackendError{Status: re.HTTPStatusCode(), Err: err}
	}
	return &BackendError{Err: err}
}
