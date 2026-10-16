package main

import (
	"crypto/tls"
	"net/http"
)

// insecureLoopbackTransport skips certificate verification. It is only used
// by the healthcheck command, which always connects to 127.0.0.1.
func insecureLoopbackTransport() http.RoundTripper {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // loopback only
}
