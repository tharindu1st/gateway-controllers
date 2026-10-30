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

// Package backchannellogout implements OpenID Connect Back-Channel Logout 1.0 for sessions
// created by the oauth2-session policy.
//
// The identity provider POSTs a signed logout token to the operation this policy is attached
// to. The policy validates it and deletes every oauth2-session session that belongs to the
// identity provider session (sid) or user (sub) it names, using the index sets oauth2-session
// writes at login. The policy always answers the request itself; nothing reaches the backend.
package backchannellogout

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// backchannelLogoutEvent is the event a logout token must carry (Back-Channel Logout §2.4).
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

	// maxBodyBytes bounds the request body; a logout token is a few kilobytes at most.
	maxBodyBytes = 64 << 10
)

// deleteIndexedSessionsScript deletes every session listed in an index set, then the set,
// atomically - so a login that adds to the set at the same moment is either fully ended or
// fully kept, never left in a set that no longer exists.
var deleteIndexedSessionsScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
for _, m in ipairs(members) do
  redis.call("DEL", ARGV[1] .. m)
end
redis.call("DEL", KEYS[1])
return #members`)

// logoutClaims are the validated logout token claims this policy acts on.
type logoutClaims struct {
	jti string
	sid string
	sub string
}

// Policy is one oauth2-session-backchannel-logout attachment.
type Policy struct {
	cfg    *config
	jwks   *jwksCache
	client *redis.Client
	now    func() time.Time
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	// The ping result is ignored: an unreachable Redis fails each request at first use.
	client, _, _ := getOrCreateRedisClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.redis.host, cfg.redis.port),
		Username:     cfg.redis.username,
		Password:     cfg.redis.password,
		DB:           cfg.redis.db,
		DialTimeout:  cfg.redis.connectionTimeout,
		ReadTimeout:  cfg.redis.readTimeout,
		WriteTimeout: cfg.redis.writeTimeout,
		PoolSize:     cfg.redis.poolSize,
	}, cfg.redis.connectionTimeout)

	slog.Debug("OAuth2SessionBackchannelLogout: policy initialized", "route", metadata.RouteName,
		"issuer", cfg.issuer, "clientId", cfg.clientID)
	return &Policy{
		cfg:    cfg,
		jwks:   newJWKSCache(cfg.jwksURI, cfg.jwksCacheTTL, cfg.jwksRequestTimeout),
		client: client,
		now:    time.Now,
	}, nil
}

// Mode buffers the request body, which carries the logout token. Attach this policy only to the
// back-channel logout operation so no other request is buffered.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody handles one back-channel logout request (Back-Channel Logout §2.5-2.8).
func (p *Policy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx.Method != http.MethodPost {
		resp := jsonResponse(http.StatusMethodNotAllowed, "method_not_allowed")
		resp.Headers["allow"] = http.MethodPost
		return resp
	}

	token, reason := extractLogoutToken(reqCtx)
	if reason != "" {
		slog.Warn("OAuth2SessionBackchannelLogout: request rejected", "reason", reason)
		return invalidRequest()
	}

	claims, err := p.validate(ctx, token)
	if err != nil {
		slog.Warn("OAuth2SessionBackchannelLogout: logout token rejected", "error", err)
		return invalidRequest()
	}

	// Each logout token is accepted once. Without this, a captured token for a user (sub) could
	// be replayed to end sessions the user started after the original logout.
	jtiKey := p.cfg.redis.keyPrefix + "bcl-jti:" + hashID(p.cfg.issuer+"\x00"+claims.jti)
	first, err := p.client.SetNX(ctx, jtiKey, "1", p.cfg.maxTokenAge+2*p.cfg.clockSkew).Result()
	if err != nil {
		slog.Error("OAuth2SessionBackchannelLogout: recording the logout token failed", "error", err)
		return logoutFailed()
	}
	if !first {
		slog.Warn("OAuth2SessionBackchannelLogout: logout token rejected", "reason", "token already used")
		return invalidRequest()
	}

	kind, value := "sid", claims.sid
	if value == "" {
		kind, value = "sub", claims.sub // no sid: end every session of the user
	}
	ended, err := p.endSessions(ctx, kind, value)
	if err != nil {
		slog.Error("OAuth2SessionBackchannelLogout: ending sessions failed", "error", err)
		// Let the identity provider retry the same token.
		if delErr := p.client.Del(context.WithoutCancel(ctx), jtiKey).Err(); delErr != nil {
			slog.Warn("OAuth2SessionBackchannelLogout: releasing the logout token failed", "error", delErr)
		}
		return logoutFailed()
	}

	slog.Info("OAuth2SessionBackchannelLogout: sessions ended", "by", kind, "sessions", ended)
	return policy.ImmediateResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"cache-control": "no-store"},
	}
}

// extractLogoutToken returns the logout_token form parameter, or a reason the request is malformed.
func extractLogoutToken(reqCtx *policy.RequestContext) (string, string) {
	contentType := ""
	if reqCtx.Headers != nil {
		if v := reqCtx.Headers.Get("content-type"); len(v) > 0 {
			contentType = v[0]
		}
	}
	if mediaType, _, err := mime.ParseMediaType(contentType); err != nil || mediaType != "application/x-www-form-urlencoded" {
		return "", "content type is not application/x-www-form-urlencoded"
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return "", "request body is empty"
	}
	if len(reqCtx.Body.Content) > maxBodyBytes {
		return "", "request body is too large"
	}
	form, err := url.ParseQuery(string(reqCtx.Body.Content))
	if err != nil {
		return "", "request body is not a valid form"
	}
	tokens := form["logout_token"]
	if len(tokens) != 1 || tokens[0] == "" {
		return "", "request must carry exactly one logout_token"
	}
	return tokens[0], ""
}

// validate checks a logout token as Back-Channel Logout §2.6 requires: signature from the
// configured identity provider with an allowed asymmetric algorithm, iss, aud, a recent iat,
// the back-channel logout event, a jti, a sid or sub, and no nonce.
func (p *Policy) validate(ctx context.Context, raw string) (*logoutClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(p.cfg.allowedAlgorithms),
		jwt.WithIssuer(p.cfg.issuer),
		jwt.WithAudience(p.cfg.clientID),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(p.cfg.clockSkew),
		jwt.WithTimeFunc(p.now),
	)
	if _, err := parser.ParseWithClaims(raw, claims, p.keyFunc(ctx)); err != nil {
		return nil, err
	}

	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, errors.New("iat claim is required")
	}
	if p.now().Sub(iat.Time) > p.cfg.maxTokenAge+p.cfg.clockSkew {
		return nil, errors.New("token is older than maxTokenAge")
	}

	events, ok := claims["events"].(map[string]interface{})
	if !ok {
		return nil, errors.New("events claim is missing")
	}
	if _, ok := events[backchannelLogoutEvent].(map[string]interface{}); !ok {
		return nil, errors.New("events claim does not contain the back-channel logout event")
	}
	// A nonce marks an ID token; refusing it stops an ID token being passed off as a logout token.
	if _, ok := claims["nonce"]; ok {
		return nil, errors.New("logout token must not contain a nonce")
	}

	out := &logoutClaims{}
	out.jti, _ = claims["jti"].(string)
	out.sid, _ = claims["sid"].(string)
	out.sub, _ = claims["sub"].(string)
	if out.jti == "" {
		return nil, errors.New("jti claim is required")
	}
	if out.sid == "" && out.sub == "" {
		return nil, errors.New("logout token must contain sid or sub")
	}
	return out, nil
}

// keyFunc looks up the token's kid in the JWKS and binds the key type to the signing method, so
// an RSA key only verifies RS/PS tokens and an EC key only ES tokens.
func (p *Policy) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		key, err := p.jwks.key(ctx, kid)
		if err != nil {
			return nil, err
		}
		switch key.(type) {
		case *rsa.PublicKey:
			switch token.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
				return key, nil
			}
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
				return key, nil
			}
		}
		return nil, fmt.Errorf("signing method %q does not match key type %T", token.Header["alg"], key)
	}
}

// endSessions deletes the sessions listed in the oauth2-session index set for one identity
// provider session (kind "sid") or user (kind "sub"), and returns how many there were.
func (p *Policy) endSessions(ctx context.Context, kind, value string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.redis.writeTimeout)
	defer cancel()
	return deleteIndexedSessionsScript.Run(ctx, p.client,
		[]string{indexKey(p.cfg.redis.keyPrefix, kind, p.cfg.issuer, value)},
		p.cfg.redis.keyPrefix+"sess:",
	).Int64()
}

// indexKey must build exactly the key oauth2-session's sessionStore.idpIndexKey builds; the
// members of the set are the suffixes of oauth2-session's "sess:" keys.
func indexKey(prefix, kind, issuer, value string) string {
	return prefix + "idp-" + kind + ":" + hashID(issuer+"\x00"+value)
}

func hashID(id string) string {
	sum := sha3.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// invalidRequest is the response for any malformed or invalid logout request. The specific
// reason is logged, not returned.
func invalidRequest() policy.ImmediateResponse {
	return jsonResponse(http.StatusBadRequest, "invalid_request")
}

// logoutFailed is returned when a valid logout couldn't be carried out. Back-Channel Logout
// §2.8 requires 400 for a failed logout as well as for an invalid one.
func logoutFailed() policy.ImmediateResponse {
	return jsonResponse(http.StatusBadRequest, "temporarily_unavailable")
}

func jsonResponse(status int, code string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": code})
	return policy.ImmediateResponse{
		StatusCode: status,
		Headers: map[string]string{
			"content-type":  "application/json",
			"cache-control": "no-store",
		},
		Body: body,
	}
}
