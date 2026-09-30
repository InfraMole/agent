// SPDX-License-Identifier: AGPL-3.0-only
// Package client talks to the InfraMole agent API (/api/agent/v1).
// Outbound only; the server can return configuration, never commands.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

var ErrUnauthorized = errors.New("unauthorized: invalid or revoked credential")

// ErrRejected wraps a 422: the server refused the report's content.
var ErrRejected = errors.New("report rejected by the server")

type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited, retry after %s", e.RetryAfter)
}

type Client struct {
	base *url.URL
	http *http.Client
	ua   string
}

// New refuses plain http unless insecureDev is set (local testing only).
func New(server string, insecureDev bool, version string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", server)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && insecureDev:
	default:
		return nil, fmt.Errorf("server must use https:// (use --insecure-dev only for local testing)")
	}
	return &Client{
		base: u,
		ua:   fmt.Sprintf("inframole-agent/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment},
			// The API never redirects; refusing prevents leaking the bearer secret elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	if err := c.post(ctx, "/api/agent/v1/enroll", "", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Report sends one report. The response's config is already clamped.
func (c *Client) Report(ctx context.Context, secret string, r protocol.Report) (*protocol.ReportResponse, error) {
	var out protocol.ReportResponse
	if err := c.post(ctx, "/api/agent/v1/report", secret, r, &out); err != nil {
		return nil, err
	}
	out.Config = protocol.ClampConfig(out.Config)
	return &out, nil
}

func (c *Client) post(ctx context.Context, path, secret string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))

	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		if out == nil {
			return nil
		}
		return json.Unmarshal(data, out)
	case res.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case res.StatusCode == http.StatusTooManyRequests:
		secs, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		if secs <= 0 {
			secs = 60
		}
		return &RateLimitedError{RetryAfter: time.Duration(secs) * time.Second}
	default:
		// Prefer the server's human message (e.g. 402 plan limit) over raw JSON.
		var body struct {
			Message string `json:"message"`
		}
		snippet := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &body) == nil && body.Message != "" {
			snippet = body.Message
		}
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		if res.StatusCode == http.StatusUnprocessableEntity {
			return fmt.Errorf("%w (422): %s", ErrRejected, snippet)
		}
		return fmt.Errorf("server returned %d: %s", res.StatusCode, snippet)
	}
}
