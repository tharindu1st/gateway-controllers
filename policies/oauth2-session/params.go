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
	"crypto/hkdf"
	"crypto/sha3"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ClientAuthMethodBasic = "client_secret_basic"
	ClientAuthMethodPost  = "client_secret_post"

	SameSiteLax    = "Lax"
	SameSiteStrict = "Strict"

	defaultLoginPath              = "/login"
	defaultCallbackPath           = "/callback"
	defaultLogoutPath             = "/logout"
	defaultPostRedirect           = "/"
	defaultCookieName             = "X-ABC"
	defaultStateCookieName        = "X-ABC-state"
	defaultIdleTimeout            = 30 * time.Minute
	defaultAbsoluteSessionTimeout = 8 * time.Hour
	defaultRefreshBuffer          = 5 * time.Minute
	defaultStateTTL               = 5 * time.Minute
	defaultTokenTTL               = time.Hour
	defaultUpstreamHeaderName     = "Authorization"
	defaultUpstreamValuePrefix    = "Bearer"
	defaultTokenRequestTimeout    = 10 * time.Second
	defaultTokenRequestMaxRetries = 2

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "oauth2-session:v1:"
	defaultRedisConnectionTimeout = 5 * time.Second
	defaultRedisReadTimeout       = 3 * time.Second
	defaultRedisWriteTimeout      = 3 * time.Second

	// minSecretBytes is the shortest sessionSigningKey/tokenEncryptionKey accepted: 256 bits.
	minSecretBytes = 32
)

// reservedAuthorizationParams are set by the policy itself and can't be overridden through
// authorizationRequestParams.
var reservedAuthorizationParams = map[string]bool{
	"response_type": true,
	"client_id":     true,
	"redirect_uri":  true,
	"state":         true,
	"scope":         true,
}

// cookieNamePattern is the RFC 6265 cookie-name token character set.
var cookieNamePattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// config is the validated configuration of one policy attachment.
type config struct {
	authorizationEndpoint      string
	tokenEndpoint              string
	clientID                   string
	clientSecret               string
	clientAuthMethod           string
	scopes                     []string
	authorizationRequestParams map[string]string
	endSessionEndpoint         string
	redirectURI                string
	issuer                     string // enables the back-channel logout index when set

	loginPath          string
	callbackPath       string
	logoutPath         string
	postLoginRedirect  string
	postLogoutRedirect string

	cookieName      string
	stateCookieName string
	cookieSameSite  string
	cookieSecure    bool

	signingKey    []byte
	encryptionKey []byte

	idleTimeout            time.Duration
	absoluteSessionTimeout time.Duration
	refreshBuffer          time.Duration
	stateTTL               time.Duration
	defaultTokenTTL        time.Duration

	upstreamHeaderName  string
	upstreamValuePrefix string

	tokenRequestTimeout    time.Duration
	tokenRequestMaxRetries int
	proxyURL               string
	tlsCaCert              string
	tlsInsecureSkipVerify  bool

	redis redisParams
}

// redisParams holds the validated systemParameters.redis values.
type redisParams struct {
	host              string
	port              int
	username          string
	password          string
	db                int
	keyPrefix         string
	connectionTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	poolSize          int
}

// parseConfig validates params and fills in defaults. Errors name the offending parameter but
// never echo a secret value.
func parseConfig(params map[string]interface{}) (*config, error) {
	c := &config{}
	var err error

	if c.authorizationEndpoint, err = requiredEndpoint(params, "authorizationEndpoint"); err != nil {
		return nil, err
	}
	if c.tokenEndpoint, err = requiredEndpoint(params, "tokenEndpoint"); err != nil {
		return nil, err
	}
	if c.clientID, err = requiredString(params, "clientId"); err != nil {
		return nil, err
	}
	if c.clientSecret, err = requiredString(params, "clientSecret"); err != nil {
		return nil, err
	}
	if c.redirectURI, err = requiredEndpoint(params, "redirectUri"); err != nil {
		return nil, err
	}

	c.clientAuthMethod = getNestedStringParam(params, "clientAuthMethod", ClientAuthMethodBasic)
	if c.clientAuthMethod != ClientAuthMethodBasic && c.clientAuthMethod != ClientAuthMethodPost {
		return nil, fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}
	c.scopes = getNestedStringListParam(params, "scopes")

	c.authorizationRequestParams = getNestedStringMapParam(params, "authorizationRequestParams")
	for k := range c.authorizationRequestParams {
		if reservedAuthorizationParams[k] {
			return nil, fmt.Errorf("'authorizationRequestParams' cannot set %q; it is set by the policy", k)
		}
	}

	if raw := getNestedStringParam(params, "endSessionEndpoint", ""); raw != "" {
		if c.endSessionEndpoint, err = validateEndpoint("endSessionEndpoint", raw); err != nil {
			return nil, err
		}
	}

	c.issuer = getNestedStringParam(params, "issuer", "")

	c.loginPath = getNestedStringParam(params, "loginPath", defaultLoginPath)
	c.callbackPath = getNestedStringParam(params, "callbackPath", defaultCallbackPath)
	c.logoutPath = getNestedStringParam(params, "logoutPath", defaultLogoutPath)
	for name, p := range map[string]string{"loginPath": c.loginPath, "callbackPath": c.callbackPath, "logoutPath": c.logoutPath} {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("'%s' must start with '/'", name)
		}
	}
	if c.loginPath == c.callbackPath || c.loginPath == c.logoutPath || c.callbackPath == c.logoutPath {
		return nil, fmt.Errorf("'loginPath', 'callbackPath' and 'logoutPath' must be different")
	}
	redirectURL, _ := url.Parse(c.redirectURI) // already validated by requiredEndpoint
	if !strings.HasSuffix(redirectURL.Path, c.callbackPath) {
		return nil, fmt.Errorf("the path of 'redirectUri' must end with 'callbackPath'")
	}

	c.postLoginRedirect = getNestedStringParam(params, "postLoginRedirect", defaultPostRedirect)
	if !isSafeRelativePath(c.postLoginRedirect) {
		return nil, fmt.Errorf("'postLoginRedirect' must be a relative path starting with a single '/'")
	}
	c.postLogoutRedirect = getNestedStringParam(params, "postLogoutRedirect", defaultPostRedirect)
	if !isSafeRelativePath(c.postLogoutRedirect) {
		return nil, fmt.Errorf("'postLogoutRedirect' must be a relative path starting with a single '/'")
	}

	c.cookieName = getNestedStringParam(params, "cookie.name", defaultCookieName)
	c.stateCookieName = getNestedStringParam(params, "cookie.stateCookieName", defaultStateCookieName)
	for name, v := range map[string]string{"cookie.name": c.cookieName, "cookie.stateCookieName": c.stateCookieName} {
		if !cookieNamePattern.MatchString(v) {
			return nil, fmt.Errorf("'%s' is not a valid cookie name", name)
		}
	}
	if c.cookieName == c.stateCookieName {
		return nil, fmt.Errorf("'cookie.name' and 'cookie.stateCookieName' must be different")
	}
	c.cookieSameSite = getNestedStringParam(params, "cookie.sameSite", SameSiteLax)
	if c.cookieSameSite != SameSiteLax && c.cookieSameSite != SameSiteStrict {
		return nil, fmt.Errorf("'cookie.sameSite' must be one of %q, %q", SameSiteLax, SameSiteStrict)
	}
	c.cookieSecure = getNestedBoolParam(params, "cookie.secure", true)
	if !c.cookieSecure {
		if strings.HasPrefix(c.cookieName, "__Host-") || strings.HasPrefix(c.cookieName, "__Secure-") ||
			strings.HasPrefix(c.stateCookieName, "__Host-") || strings.HasPrefix(c.stateCookieName, "__Secure-") {
			return nil, fmt.Errorf("cookie names with the __Host- or __Secure- prefix require 'cookie.secure' to be true")
		}
		slog.Warn("OAuth2Session: cookie.secure is disabled - session cookies will be sent over plain HTTP; never use this outside local testing")
	}

	signingSecret, err := requiredSecret(params, "sessionSigningKey")
	if err != nil {
		return nil, err
	}
	encryptionSecret, err := requiredSecret(params, "tokenEncryptionKey")
	if err != nil {
		return nil, err
	}
	// HKDF turns operator-supplied secrets of any length >= 32 bytes into fixed-size keys, with
	// distinct labels so the two keys never coincide even if the same secret is used for both.
	if c.signingKey, err = hkdf.Key(sha3.New256, []byte(signingSecret), nil, "oauth2-session cookie signing v1", 32); err != nil {
		return nil, fmt.Errorf("deriving session signing key: %w", err)
	}
	if c.encryptionKey, err = hkdf.Key(sha3.New256, []byte(encryptionSecret), nil, "oauth2-session token encryption v1", 32); err != nil {
		return nil, fmt.Errorf("deriving token encryption key: %w", err)
	}

	c.idleTimeout = getNestedPositiveDurationParam(params, "idleTimeout", defaultIdleTimeout)
	c.absoluteSessionTimeout = getNestedPositiveDurationParam(params, "absoluteSessionTimeout", defaultAbsoluteSessionTimeout)
	c.refreshBuffer = getNestedDurationParam(params, "refreshBuffer", defaultRefreshBuffer)
	if c.refreshBuffer < 0 {
		c.refreshBuffer = defaultRefreshBuffer
	}
	c.stateTTL = getNestedPositiveDurationParam(params, "stateTTL", defaultStateTTL)
	c.defaultTokenTTL = getNestedPositiveDurationParam(params, "defaultTokenTTL", defaultTokenTTL)

	c.upstreamHeaderName = getNestedStringParam(params, "upstreamHeaderName", defaultUpstreamHeaderName)
	c.upstreamValuePrefix = defaultUpstreamValuePrefix
	if v, ok := getNestedParam(params, "upstreamValuePrefix"); ok {
		if s, ok := v.(string); ok {
			// An explicit empty string is honored as "no prefix".
			c.upstreamValuePrefix = strings.TrimSpace(s)
		}
	}

	c.tokenRequestTimeout = getNestedPositiveDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	c.tokenRequestMaxRetries = getNestedIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)
	if c.tokenRequestMaxRetries < 0 {
		c.tokenRequestMaxRetries = defaultTokenRequestMaxRetries
	}
	c.proxyURL = getNestedStringParam(params, "proxyURL", "")
	c.tlsCaCert = getNestedStringParam(params, "tlsCaCert", "")
	c.tlsInsecureSkipVerify = getNestedBoolParam(params, "tlsInsecureSkipVerify", false)
	if c.tlsInsecureSkipVerify {
		slog.Warn("OAuth2Session: tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoint is disabled; this must never be used against a real identity provider")
	}

	c.redis = redisParams{
		host:              getNestedStringParam(params, "redis.host", defaultRedisHost),
		port:              getNestedIntParam(params, "redis.port", defaultRedisPort),
		username:          getNestedStringParam(params, "redis.username", ""),
		password:          getNestedStringParam(params, "redis.password", ""),
		db:                getNestedIntParam(params, "redis.db", 0),
		keyPrefix:         getNestedStringParam(params, "redis.keyPrefix", defaultRedisKeyPrefix),
		connectionTimeout: getNestedPositiveDurationParam(params, "redis.connectionTimeout", defaultRedisConnectionTimeout),
		readTimeout:       getNestedPositiveDurationParam(params, "redis.readTimeout", defaultRedisReadTimeout),
		writeTimeout:      getNestedPositiveDurationParam(params, "redis.writeTimeout", defaultRedisWriteTimeout),
		poolSize:          getNestedIntParam(params, "redis.poolSize", 0),
	}

	return c, nil
}

// requiredString returns a non-empty, trimmed string parameter.
func requiredString(params map[string]interface{}, key string) (string, error) {
	v, ok := getNestedParam(params, key)
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return s, nil
}

// requiredSecret is requiredString plus a minimum length, so a weak signing or encryption
// secret is rejected at deploy time. The value itself is never included in the error.
func requiredSecret(params map[string]interface{}, key string) (string, error) {
	s, err := requiredString(params, key)
	if err != nil {
		return "", err
	}
	if len(s) < minSecretBytes {
		return "", fmt.Errorf("'%s' must be at least %d bytes long", key, minSecretBytes)
	}
	return s, nil
}

// requiredEndpoint returns a required absolute http(s) URL parameter.
func requiredEndpoint(params map[string]interface{}, key string) (string, error) {
	s, err := requiredString(params, key)
	if err != nil {
		return "", err
	}
	return validateEndpoint(key, s)
}

// validateEndpoint checks that raw is an absolute http(s) URL with a host and no fragment or
// userinfo. Endpoints come only from configuration, never from a request.
func validateEndpoint(key, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("'%s' must be an absolute http or https URL", key)
	}
	if u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("'%s' must not contain credentials or a fragment", key)
	}
	return raw, nil
}

// getNestedParam resolves a dotted key ("redis.host") against params, tolerating
// either nested maps or a flattened key.
func getNestedParam(params map[string]interface{}, dottedKey string) (interface{}, bool) {
	if v, ok := params[dottedKey]; ok {
		return v, true
	}
	var cur interface{} = params
	for _, part := range strings.Split(dottedKey, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func getNestedStringParam(params map[string]interface{}, dottedKey, def string) string {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return def
}

func getNestedIntParam(params map[string]interface{}, dottedKey string, def int) int {
	if v, ok := getNestedParam(params, dottedKey); ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func getNestedBoolParam(params map[string]interface{}, dottedKey string, def bool) bool {
	if v, ok := getNestedParam(params, dottedKey); ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			if parsed, err := strconv.ParseBool(strings.TrimSpace(b)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func getNestedDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
				return d
			}
		}
	}
	return def
}

// getNestedPositiveDurationParam falls back to def when the parsed duration is <= 0.
func getNestedPositiveDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	d := getNestedDurationParam(params, dottedKey, def)
	if d <= 0 {
		return def
	}
	return d
}

// getNestedStringListParam returns the non-empty strings of a list parameter.
func getNestedStringListParam(params map[string]interface{}, dottedKey string) []string {
	v, ok := getNestedParam(params, dottedKey)
	if !ok {
		return nil
	}
	var out []string
	switch list := v.(type) {
	case []interface{}:
		for _, item := range list {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range list {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

// getNestedStringMapParam returns the non-empty string entries of a flat map parameter.
func getNestedStringMapParam(params map[string]interface{}, dottedKey string) map[string]string {
	v, ok := getNestedParam(params, dottedKey)
	if !ok {
		return nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
			out[k] = strings.TrimSpace(s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
