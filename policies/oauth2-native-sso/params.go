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

	// DefaultActorTokenType is the device_secret token type of OpenID Connect Native SSO for
	// Mobile Apps 1.0.
	DefaultActorTokenType = "urn:openid:params:token-type:device-secret"
	// TokenTypeIDToken is the RFC 8693 token type of an id_token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// Source session tokens that can be placed in the exchange as subject_token or actor_token.
	SourceTokenIDToken      = "id_token"
	SourceTokenDeviceSecret = "device_secret"
	SourceTokenNone         = "none" // actorToken only: no actor_token is sent

	defaultLoginPath              = "/login"
	defaultPostRedirect           = "/"
	defaultIdleTimeout            = 30 * time.Minute
	defaultAbsoluteSessionTimeout = 8 * time.Hour
	defaultTokenTTL               = time.Hour
	defaultTokenRequestTimeout    = 10 * time.Second
	defaultTokenRequestMaxRetries = 2

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "oauth2-session:v1:"
	defaultRedisConnectionTimeout = 5 * time.Second
	defaultRedisReadTimeout       = 3 * time.Second
	defaultRedisWriteTimeout      = 3 * time.Second

	// minSecretBytes is the shortest signing/encryption secret accepted: 256 bits.
	minSecretBytes = 32

	// The HKDF labels oauth2-session derives its keys with. They must stay identical to
	// policies/oauth2-session/params.go, or cookies and records won't verify across the policies.
	hkdfSigningInfo    = "oauth2-session cookie signing v1"
	hkdfEncryptionInfo = "oauth2-session token encryption v1"
)

// defaultScopes is sent when no scopes are configured; the exchange then yields an id_token.
var defaultScopes = []string{"openid"}

// cookieNamePattern is the RFC 6265 cookie-name token character set.
var cookieNamePattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// sessionSide is the oauth2-session attachment whose cookies and Redis records one side of the
// exchange reads (source, API A) or writes (target, API B).
type sessionSide struct {
	cookieName             string
	signingKey             []byte
	encryptionKey          []byte
	idleTimeout            time.Duration // target only
	absoluteSessionTimeout time.Duration
	cookieSameSite         string // target only
	cookieSecure           bool   // target only
}

// config is the validated configuration of one policy attachment.
type config struct {
	tokenEndpoint    string
	clientID         string
	clientSecret     string
	clientAuthMethod string
	scopes           []string
	audience         string
	resource         string // RFC 8707 resource indicator; empty = not sent
	issuer           string

	// The token exchange layout: which source token is the subject and which the actor, and the
	// token type sent for each. Native SSO 1.0 §4 is subject=id_token, actor=device_secret.
	subjectToken     string
	subjectTokenType string
	actorToken       string // SourceTokenNone sends no actor_token
	actorTokenType   string

	loginPath         string
	postLoginRedirect string
	transparentSSO    bool

	source sessionSide
	target sessionSide

	defaultTokenTTL        time.Duration
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

	allowInsecure := getNestedBoolParam(params, "allowInsecureTokenEndpoint", false)
	if c.tokenEndpoint, err = requiredString(params, "tokenEndpoint"); err != nil {
		return nil, err
	}
	if c.tokenEndpoint, err = validateEndpoint("tokenEndpoint", c.tokenEndpoint, allowInsecure); err != nil {
		return nil, err
	}
	if allowInsecure {
		slog.Warn("OAuth2NativeSSO: allowInsecureTokenEndpoint is enabled - tokenEndpoint may use plain HTTP; never use this outside local testing")
	}
	if c.clientID, err = requiredString(params, "clientId"); err != nil {
		return nil, err
	}
	if c.clientSecret, err = requiredString(params, "clientSecret"); err != nil {
		return nil, err
	}
	c.clientAuthMethod = getNestedStringParam(params, "clientAuthMethod", ClientAuthMethodBasic)
	if c.clientAuthMethod != ClientAuthMethodBasic && c.clientAuthMethod != ClientAuthMethodPost {
		return nil, fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}
	c.scopes = getNestedStringListParam(params, "scopes")
	if len(c.scopes) == 0 {
		c.scopes = defaultScopes
	}
	c.issuer = getNestedStringParam(params, "issuer", "")
	// Native SSO §4: the audience is the issuer of the OpenID Provider that issued the id_token.
	c.audience = getNestedStringParam(params, "audience", c.issuer)
	if c.audience == "" {
		return nil, fmt.Errorf("'audience' is required when 'issuer' is not set")
	}
	if err := parseExchangeLayout(c, params); err != nil {
		return nil, err
	}

	// RFC 8707 §2: an absolute URI without a fragment. It asks for an access token for that API,
	// as a resource parameter on the target API's own login would.
	if c.resource = getNestedStringParam(params, "resource", ""); c.resource != "" {
		u, err := url.Parse(c.resource)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return nil, fmt.Errorf("'resource' must be an absolute URI without a fragment")
		}
	}

	c.loginPath = getNestedStringParam(params, "loginPath", defaultLoginPath)
	if !strings.HasPrefix(c.loginPath, "/") {
		return nil, fmt.Errorf("'loginPath' must start with '/'")
	}
	c.postLoginRedirect = getNestedStringParam(params, "postLoginRedirect", defaultPostRedirect)
	if !isSafeRelativePath(c.postLoginRedirect) {
		return nil, fmt.Errorf("'postLoginRedirect' must be a relative path starting with a single '/'")
	}
	c.transparentSSO = getNestedBoolParam(params, "transparentSso", false)

	if c.source, err = parseSide(params, "source", false); err != nil {
		return nil, err
	}
	if c.target, err = parseSide(params, "target", true); err != nil {
		return nil, err
	}
	if c.source.cookieName == c.target.cookieName {
		return nil, fmt.Errorf("'source.cookieName' and 'target.cookieName' must be different")
	}

	c.defaultTokenTTL = getNestedPositiveDurationParam(params, "defaultTokenTTL", defaultTokenTTL)
	c.tokenRequestTimeout = getNestedPositiveDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	c.tokenRequestMaxRetries = getNestedIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)
	if c.tokenRequestMaxRetries < 0 {
		c.tokenRequestMaxRetries = defaultTokenRequestMaxRetries
	}
	c.proxyURL = getNestedStringParam(params, "proxyURL", "")
	c.tlsCaCert = getNestedStringParam(params, "tlsCaCert", "")
	c.tlsInsecureSkipVerify = getNestedBoolParam(params, "tlsInsecureSkipVerify", false)
	if c.tlsInsecureSkipVerify {
		slog.Warn("OAuth2NativeSSO: tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoint is disabled; this must never be used against a real identity provider")
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

// parseSide reads the "source" or "target" object. Its secrets go through the same HKDF
// derivation as oauth2-session, so the same configured secret yields the same keys.
func parseSide(params map[string]interface{}, prefix string, isTarget bool) (sessionSide, error) {
	s := sessionSide{}
	var err error
	if s.cookieName, err = requiredString(params, prefix+".cookieName"); err != nil {
		return s, err
	}
	if !cookieNamePattern.MatchString(s.cookieName) {
		return s, fmt.Errorf("'%s.cookieName' is not a valid cookie name", prefix)
	}
	signingSecret, err := requiredSecret(params, prefix+".sessionSigningKey")
	if err != nil {
		return s, err
	}
	encryptionSecret, err := requiredSecret(params, prefix+".tokenEncryptionKey")
	if err != nil {
		return s, err
	}
	if s.signingKey, err = hkdf.Key(sha3.New256, []byte(signingSecret), nil, hkdfSigningInfo, 32); err != nil {
		return s, fmt.Errorf("deriving %s session signing key: %w", prefix, err)
	}
	if s.encryptionKey, err = hkdf.Key(sha3.New256, []byte(encryptionSecret), nil, hkdfEncryptionInfo, 32); err != nil {
		return s, fmt.Errorf("deriving %s token encryption key: %w", prefix, err)
	}
	s.absoluteSessionTimeout = getNestedPositiveDurationParam(params, prefix+".absoluteSessionTimeout", defaultAbsoluteSessionTimeout)
	if !isTarget {
		return s, nil
	}

	s.idleTimeout = getNestedPositiveDurationParam(params, prefix+".idleTimeout", defaultIdleTimeout)
	s.cookieSameSite = getNestedStringParam(params, prefix+".sameSite", SameSiteLax)
	if s.cookieSameSite != SameSiteLax && s.cookieSameSite != SameSiteStrict {
		return s, fmt.Errorf("'%s.sameSite' must be one of %q, %q", prefix, SameSiteLax, SameSiteStrict)
	}
	s.cookieSecure = getNestedBoolParam(params, prefix+".secure", true)
	if !s.cookieSecure {
		if strings.HasPrefix(s.cookieName, "__Host-") || strings.HasPrefix(s.cookieName, "__Secure-") {
			return s, fmt.Errorf("cookie names with the __Host- or __Secure- prefix require '%s.secure' to be true", prefix)
		}
		slog.Warn("OAuth2NativeSSO: target.secure is disabled - session cookies will be sent over plain HTTP; never use this outside local testing")
	}
	return s, nil
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

// requiredSecret is requiredString plus a minimum length. The value is never included in errors.
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

// validateEndpoint checks that raw is an absolute https URL (http only with allowInsecure) with a
// host and no fragment or userinfo. Endpoints come only from configuration, never from a request.
func validateEndpoint(key, raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(allowInsecure && u.Scheme == "http")) {
		if allowInsecure {
			return "", fmt.Errorf("'%s' must be an absolute http or https URL", key)
		}
		return "", fmt.Errorf("'%s' must be an absolute https URL", key)
	}
	if u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("'%s' must not contain credentials or a fragment", key)
	}
	return raw, nil
}

// getNestedParam resolves a dotted key ("redis.host") against params, tolerating either nested
// maps or a flattened key.
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

// getNestedPositiveDurationParam falls back to def when the value is missing, invalid or <= 0.
func getNestedPositiveDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
				return d
			}
		}
	}
	return def
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

// defaultTokenTypes is the token type sent for each source token unless configured.
var defaultTokenTypes = map[string]string{
	SourceTokenIDToken:      TokenTypeIDToken,
	SourceTokenDeviceSecret: DefaultActorTokenType,
}

// parseExchangeLayout reads which source token goes in subject_token and actor_token, and their
// token types. The defaults are the Native SSO 1.0 layout; identity providers that implement it
// differently (for example with the device_secret as the subject) are configured here.
func parseExchangeLayout(c *config, params map[string]interface{}) error {
	c.subjectToken = getNestedStringParam(params, "subjectToken", SourceTokenIDToken)
	if _, ok := defaultTokenTypes[c.subjectToken]; !ok {
		return fmt.Errorf("'subjectToken' must be one of %q, %q", SourceTokenIDToken, SourceTokenDeviceSecret)
	}
	// The actor defaults to the other source token, so swapping the subject swaps the pair.
	defaultActor := SourceTokenDeviceSecret
	if c.subjectToken == SourceTokenDeviceSecret {
		defaultActor = SourceTokenIDToken
	}
	c.actorToken = getNestedStringParam(params, "actorToken", defaultActor)
	if _, ok := defaultTokenTypes[c.actorToken]; !ok && c.actorToken != SourceTokenNone {
		return fmt.Errorf("'actorToken' must be one of %q, %q, %q", SourceTokenIDToken, SourceTokenDeviceSecret, SourceTokenNone)
	}
	if c.actorToken == c.subjectToken {
		return fmt.Errorf("'subjectToken' and 'actorToken' must be different")
	}
	// The exchange always needs the device_secret: it is what proves the device's SSO session.
	if c.subjectToken != SourceTokenDeviceSecret && c.actorToken != SourceTokenDeviceSecret {
		return fmt.Errorf("either 'subjectToken' or 'actorToken' must be %q", SourceTokenDeviceSecret)
	}

	var err error
	if c.subjectTokenType, err = tokenTypeParam(params, "subjectTokenType", defaultTokenTypes[c.subjectToken]); err != nil {
		return err
	}
	if c.actorToken == SourceTokenNone {
		if _, set := getNestedParam(params, "actorTokenType"); set {
			return fmt.Errorf("'actorTokenType' must not be set when 'actorToken' is %q", SourceTokenNone)
		}
		return nil
	}
	c.actorTokenType, err = tokenTypeParam(params, "actorTokenType", defaultTokenTypes[c.actorToken])
	return err
}

// tokenTypeParam returns an RFC 8693 token type: an absolute URI, such as a URN.
func tokenTypeParam(params map[string]interface{}, key, def string) (string, error) {
	v := strings.TrimSpace(getNestedStringParam(params, key, def))
	if u, err := url.Parse(v); err != nil || !u.IsAbs() || strings.ContainsAny(v, " \t\r\n") {
		return "", fmt.Errorf("'%s' must be an absolute URI, such as urn:ietf:params:oauth:token-type:jwt", key)
	}
	return v, nil
}
