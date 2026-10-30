/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package oauth2session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// maxTokenResponseBytes bounds how much of a token response is read, regardless of
	// Content-Length, so a misbehaving IdP can't exhaust memory.
	maxTokenResponseBytes = 1 << 20 // 1MiB

	// retryBaseDelay/retryMaxDelay bound the exponential backoff between token-endpoint retries,
	// with jitter so replicas don't retry a struggling IdP in lockstep.
	retryBaseDelay = 100 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
)

// tokenResponse is the subset of an RFC 6749 §5.1 token response this policy keeps.
type tokenResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	IDToken      string
	Scopes       []string
	Expiry       time.Time
}

// TokenError represents an RFC 6749 §5.2 error response FROM the token endpoint, as opposed to a
// network-level failure that never got a response at all.
type TokenError struct {
	StatusCode int
	ErrorCode  string
}

func (e *TokenError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("token endpoint returned %d %s", e.StatusCode, e.ErrorCode)
	}
	return fmt.Sprintf("token endpoint returned status %d", e.StatusCode)
}

// isRejection reports whether err is a definitive 4xx rejection of the grant (for example
// invalid_grant for a revoked refresh token), as opposed to a transient IdP or network failure.
func isRejection(err error) bool {
	var tokErr *TokenError
	return errors.As(err, &tokErr) && tokErr.StatusCode >= 400 && tokErr.StatusCode < 500 &&
		tokErr.StatusCode != http.StatusTooManyRequests
}

// tokenJSON is the raw shape of an RFC 6749 §5.1 token response. ExpiresIn is left as
// json.RawMessage since some IdPs send it as a JSON string instead of a number.
type tokenJSON struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	Scope        string          `json:"scope"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
}

func (t tokenJSON) expiresInSeconds() (int64, bool) {
	if len(t.ExpiresIn) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(t.ExpiresIn, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(t.ExpiresIn, &s); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// tokenClient calls the IdP token endpoint for the authorization code and refresh token grants.
type tokenClient struct {
	endpoint     string
	clientID     string
	clientSecret string
	authMethod   string
	redirectURI  string
	defaultTTL   time.Duration
	maxRetries   int
	httpClient   *http.Client
	now          func() time.Time
}

func newTokenClient(c *config) (*tokenClient, error) {
	transport, err := getOrCreateTokenEndpointTransport(c)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint transport config: %w", err)
	}
	return &tokenClient{
		endpoint:     c.tokenEndpoint,
		clientID:     c.clientID,
		clientSecret: c.clientSecret,
		authMethod:   c.clientAuthMethod,
		redirectURI:  c.redirectURI,
		defaultTTL:   c.defaultTokenTTL,
		maxRetries:   c.tokenRequestMaxRetries,
		httpClient:   &http.Client{Timeout: c.tokenRequestTimeout, Transport: transport},
		now:          time.Now,
	}, nil
}

// exchangeCode redeems an authorization code (RFC 6749 §4.1.3).
func (c *tokenClient) exchangeCode(ctx context.Context, code string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeAuthorizationCode)
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURI)
	return c.doWithRetry(ctx, form)
}

// refresh redeems a refresh token (RFC 6749 §6).
func (c *tokenClient) refresh(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeRefreshToken)
	form.Set("refresh_token", refreshToken)
	return c.doWithRetry(ctx, form)
}

// doWithRetry retries only on 429/5xx. A network error is NOT retried: the IdP may already have
// redeemed the single-use code or rotated the refresh token, and a replay would then fail with
// invalid_grant and end the session.
func (c *tokenClient) doWithRetry(ctx context.Context, form url.Values) (*tokenResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(retryBackoff(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		tok, err := c.do(ctx, form)
		if err == nil {
			return tok, nil
		}
		lastErr = err
		var tokErr *TokenError
		if !errors.As(err, &tokErr) || (tokErr.StatusCode != http.StatusTooManyRequests && tokErr.StatusCode < 500) {
			return nil, err
		}
	}
	return nil, lastErr
}

// do POSTs form to the token endpoint and parses the response. client_secret_basic form-urlencodes
// the ID and secret before combining them (RFC 6749 Appendix B), so a colon in either survives.
func (c *tokenClient) do(ctx context.Context, form url.Values) (*tokenResponse, error) {
	if c.authMethod == ClientAuthMethodPost {
		form.Set("client_id", c.clientID)
		form.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.authMethod != ClientAuthMethodPost {
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %s", redactURLCredentials(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	if len(body) > maxTokenResponseBytes {
		return nil, fmt.Errorf("token response exceeded %d bytes", maxTokenResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		tokErr := &TokenError{StatusCode: resp.StatusCode}
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errBody) == nil {
			tokErr.ErrorCode = sanitizeErrorCode(errBody.Error)
		}
		return nil, tokErr
	}

	var parsed tokenJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint response is missing access_token")
	}

	tok := &tokenResponse{
		AccessToken:  parsed.AccessToken,
		TokenType:    parsed.TokenType,
		RefreshToken: parsed.RefreshToken,
		IDToken:      parsed.IDToken,
		Scopes:       strings.Fields(parsed.Scope),
		Expiry:       c.now().Add(c.defaultTTL),
	}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	if secs, ok := parsed.expiresInSeconds(); ok && secs > 0 {
		tok.Expiry = c.now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}

// errorCodePattern is the RFC 6749 error-code character set; anything else is dropped before logging.
var errorCodePattern = regexp.MustCompile(`^[\x20-\x21\x23-\x5B\x5D-\x7E]{1,64}$`)

// sanitizeErrorCode keeps an IdP-supplied error code only if it is short and printable, so a
// hostile or broken IdP can't inject arbitrary text into logs.
func sanitizeErrorCode(s string) string {
	if errorCodePattern.MatchString(s) {
		return s
	}
	return ""
}

// retryBackoff returns the delay before retry attempt n (n >= 1): exponential from
// retryBaseDelay, capped at retryMaxDelay, plus up to 50% jitter.
func retryBackoff(attempt int) time.Duration {
	backoff := retryBaseDelay * time.Duration(uint64(1)<<uint(attempt-1))
	if backoff > retryMaxDelay || backoff <= 0 {
		backoff = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(backoff)/2 + 1))
	return backoff + jitter
}

// tokenEndpointTransportKey identifies a distinct token-endpoint HTTP client configuration.
type tokenEndpointTransportKey struct {
	proxyURL              string
	tlsCACert             string
	tlsInsecureSkipVerify bool
}

// tokenEndpointTransports is the process-wide registry of shared *http.Transport values, keyed
// by proxy/TLS configuration - mirrors redisClients (redis_clients.go).
var tokenEndpointTransports = newKeyedSingleton[tokenEndpointTransportKey, *http.Transport]()

func getOrCreateTokenEndpointTransport(c *config) (*http.Transport, error) {
	key := tokenEndpointTransportKey{
		proxyURL:              c.proxyURL,
		tlsCACert:             c.tlsCaCert,
		tlsInsecureSkipVerify: c.tlsInsecureSkipVerify,
	}
	transport, _, err := tokenEndpointTransports.getOrCreate(key, func() (*http.Transport, error) {
		return buildTokenEndpointTransport(c)
	})
	return transport, err
}

// buildTokenEndpointTransport sets Proxy explicitly alongside TLSClientConfig - an unset
// Transport.Proxy means "never proxy", not ProxyFromEnvironment.
func buildTokenEndpointTransport(c *config) (*http.Transport, error) {
	proxyFunc := http.ProxyFromEnvironment
	if c.proxyURL != "" {
		proxyURL, err := url.Parse(c.proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxyURL: %s", redactURLCredentials(err.Error()))
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	transport := &http.Transport{Proxy: proxyFunc}
	if c.tlsCaCert != "" || c.tlsInsecureSkipVerify {
		tlsConfig := &tls.Config{InsecureSkipVerify: c.tlsInsecureSkipVerify} //nolint:gosec // opt-in, logged at parse time
		if c.tlsCaCert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(c.tlsCaCert)) {
				return nil, fmt.Errorf("tlsCaCert: no valid PEM certificates found")
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}
	return transport, nil
}

// credentialedURLPattern captures a "scheme://" prefix immediately followed by a "userinfo@"
// segment, so redactURLCredentials can strip just the latter.
var credentialedURLPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// redactURLCredentials scrubs any "scheme://user:pass@" userinfo out of s.
func redactURLCredentials(s string) string {
	return credentialedURLPattern.ReplaceAllString(s, "${1}[REDACTED]@")
}
