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

package oauth2nativesso

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	// retryBaseDelay/retryMaxDelay bound the exponential backoff between token-endpoint retries.
	retryBaseDelay = 100 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// tokenResponse is the subset of a Native SSO token exchange response this policy keeps.
type tokenResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	IDToken      string
	DeviceSecret string
	Scopes       []string
	Expiry       time.Time
}

// TokenError is an RFC 6749 §5.2 error response from the token endpoint.
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

// tokenJSON is the raw response shape. ExpiresIn is json.RawMessage since some IdPs send it as a
// string.
type tokenJSON struct {
	AccessToken     string          `json:"access_token"`
	IssuedTokenType string          `json:"issued_token_type"`
	TokenType       string          `json:"token_type"`
	RefreshToken    string          `json:"refresh_token"`
	IDToken         string          `json:"id_token"`
	DeviceSecret    string          `json:"device_secret"`
	Scope           string          `json:"scope"`
	ExpiresIn       json.RawMessage `json:"expires_in"`
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

// tokenClient performs the Native SSO token exchange for the target client.
type tokenClient struct {
	endpoint     string
	clientID     string
	clientSecret string
	authMethod   string
	audience     string
	resource     string
	scopes       []string
	defaultTTL   time.Duration

	subjectToken     string
	subjectTokenType string
	actorToken       string
	actorTokenType   string

	maxRetries int
	httpClient *http.Client
	now        func() time.Time
	log        *slog.Logger // never given the form, the credentials or the response body
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
		audience:     c.audience,
		resource:     c.resource,
		scopes:       c.scopes,
		defaultTTL:   c.defaultTokenTTL,

		subjectToken:     c.subjectToken,
		subjectTokenType: c.subjectTokenType,
		actorToken:       c.actorToken,
		actorTokenType:   c.actorTokenType,

		maxRetries: c.tokenRequestMaxRetries,
		httpClient: &http.Client{
			Timeout:   c.tokenRequestTimeout,
			Transport: transport,
			// A token endpoint never legitimately redirects; following one would replay the
			// id_token and device_secret to wherever the Location points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
		log: slog.Default(),
	}, nil
}

// exchange performs the OpenID Connect Native SSO token exchange. By default it is the Native SSO
// for Mobile Apps 1.0 layout (§4): the id_token is the subject and the device_secret the actor;
// subjectToken, actorToken and their token types change which token goes where.
func (c *tokenClient) exchange(ctx context.Context, idToken, deviceSecret string) (*tokenResponse, error) {
	source := map[string]string{SourceTokenIDToken: idToken, SourceTokenDeviceSecret: deviceSecret}
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("audience", c.audience)
	form.Set("subject_token", source[c.subjectToken])
	form.Set("subject_token_type", c.subjectTokenType)
	if c.actorToken != SourceTokenNone {
		form.Set("actor_token", source[c.actorToken])
		form.Set("actor_token_type", c.actorTokenType)
	}
	if len(c.scopes) > 0 {
		form.Set("scope", strings.Join(c.scopes, " "))
	}
	if c.resource != "" {
		form.Set("resource", c.resource)
	}
	return c.doWithRetry(ctx, form)
}

// doWithRetry retries only on 429/5xx. A network error is not retried, since the IdP may already
// have processed the exchange (for example rotating the device_secret).
func (c *tokenClient) doWithRetry(ctx context.Context, form url.Values) (*tokenResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBackoff(attempt)
			c.log.Debug("OAuth2NativeSSO: retrying the token exchange", "attempt", attempt+1, "of", c.maxRetries+1, "backoff", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		start := time.Now()
		tok, err := c.do(ctx, form)
		if err == nil {
			c.log.Debug("OAuth2NativeSSO: token endpoint answered 200", "attempt", attempt+1, "elapsed", time.Since(start))
			return tok, nil
		}
		lastErr = err
		var tokErr *TokenError
		retryable := errors.As(err, &tokErr) && (tokErr.StatusCode == http.StatusTooManyRequests || tokErr.StatusCode >= 500)
		// err holds only the status, a sanitised OAuth error code or a transport error with
		// credentials redacted - never the request form or the response body.
		c.log.Debug("OAuth2NativeSSO: token exchange attempt failed", "attempt", attempt+1, "elapsed", time.Since(start),
			"retryable", retryable, "error", err)
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// do POSTs form to the token endpoint and parses the response. client_secret_basic
// form-urlencodes the ID and secret before combining them (RFC 6749 Appendix B).
func (c *tokenClient) do(ctx context.Context, form url.Values) (*tokenResponse, error) {
	if c.authMethod == ClientAuthMethodPost {
		form.Set("client_id", c.clientID)
		form.Set("client_secret", c.clientSecret)
	} else {
		// Native SSO §4 lists client_id as a request parameter; it is harmless next to Basic auth.
		form.Set("client_id", c.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	c.log.Debug("OAuth2NativeSSO: calling the token endpoint", "endpoint", redactURLCredentials(c.endpoint),
		"clientAuthMethod", c.authMethod, "grantType", form.Get("grant_type"), "subjectTokenType", form.Get("subject_token_type"),
		"actorTokenType", form.Get("actor_token_type"), "audience", form.Get("audience"), "scope", form.Get("scope"),
		"resource", form.Get("resource"))
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
		DeviceSecret: parsed.DeviceSecret,
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

// sanitizeErrorCode keeps an IdP-supplied error code only if it is short and printable.
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

// tokenEndpointTransports is the process-wide registry of shared *http.Transport values.
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

// credentialedURLPattern captures a "scheme://" prefix immediately followed by a "userinfo@" segment.
var credentialedURLPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// redactURLCredentials scrubs any "scheme://user:pass@" userinfo out of s.
func redactURLCredentials(s string) string {
	return credentialedURLPattern.ReplaceAllString(s, "${1}[REDACTED]@")
}
