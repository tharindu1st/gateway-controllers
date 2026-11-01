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

// Package oauth2nativesso signs a browser in to one API (the target) from the oauth2-session
// login it already has on another API (the source), without a round trip to the identity
// provider, using the OpenID Connect Native SSO for Mobile Apps 1.0 token exchange.
//
// The source session's id_token (subject) and device_secret (actor) are exchanged at the token
// endpoint for the target client's tokens. They are stored as a brand-new session in
// oauth2-session's Redis format, and the browser gets the target's session cookie with a
// redirect. From then on the target API's own oauth2-session policy serves that session:
// refresh, upstream bearer token, userinfo, logout and back-channel logout.
//
// Attach it to the target API before its oauth2-session policy. Any condition that prevents
// SSO - no source session, an expired one, no device_secret, a rejected exchange, Redis
// unavailable - lets the request continue unchanged, so oauth2-session runs its normal login.
package oauth2nativesso

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// handoffTTL is how long the request that ran an exchange leaves the new target session for
	// concurrent requests of the same browser, and the window of the transparent redirect guard.
	handoffTTL = 30 * time.Second

	// maxTransparentRedirects bounds transparent SSO redirects per source session within
	// handoffTTL, so a browser that doesn't store the cookie can't loop.
	maxTransparentRedirects = 10

	// lockPollInterval is how often a request waiting on another request's exchange re-checks.
	lockPollInterval = 50 * time.Millisecond
)

// errNoSSO means the request can't be signed in with Native SSO; it continues unchanged.
var errNoSSO = errors.New("native sso not possible")

// Policy is one oauth2-native-sso attachment.
type Policy struct {
	cfg     *config
	log     *slog.Logger // carries the route; request logs never include session IDs, tokens or user claims
	store   *sessionStore
	tokens  *tokenClient
	now     func() time.Time
	lockTTL time.Duration
}

// GetPolicy is the v1alpha2 factory entry point. Configuration errors surface here, at deploy time.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// The ping result is ignored: an unreachable Redis just means no SSO until it is back.
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

	store, err := newSessionStore(client, cfg.redis, cfg.source.encryptionKey, cfg.target.encryptionKey)
	if err != nil {
		return nil, err
	}
	tokens, err := newTokenClient(cfg)
	if err != nil {
		return nil, err
	}

	p := newPolicy(cfg, store, tokens)
	p.log = p.log.With("route", metadata.RouteName)
	tokens.log = p.log
	p.log.Debug("OAuth2NativeSSO: policy initialized", "clientId", cfg.clientID, "loginPath", cfg.loginPath,
		"transparentSso", cfg.transparentSSO, "sourceCookie", cfg.source.cookieName, "targetCookie", cfg.target.cookieName,
		"issuerCheck", cfg.issuer != "", "resourceIndicator", cfg.resource != "", "scopes", cfg.scopes,
		"clientAuthMethod", cfg.clientAuthMethod, "lockTtl", p.lockTTL)
	return p, nil
}

func newPolicy(cfg *config, store *sessionStore, tokens *tokenClient) *Policy {
	retries := time.Duration(cfg.tokenRequestMaxRetries)
	return &Policy{
		cfg:    cfg,
		log:    slog.Default(),
		store:  store,
		tokens: tokens,
		now:    time.Now,
		// Long enough to cover an exchange with all its retries and jittered backoff.
		lockTTL: cfg.tokenRequestTimeout*(retries+1) + 3*retryMaxDelay/2*retries + time.Second,
	}
}

// Mode processes request headers only; SSO always answers before the body is read.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders signs the browser in to the target API when it has a source session but no
// target session. It dispatches on the operation path the router matched, never on the raw path.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	pass := policy.UpstreamRequestHeaderModifications{}
	op := ""
	if reqCtx.SharedContext != nil {
		op = reqCtx.OperationPath
	}
	ds := reqCtx.DownstreamRequest()
	// Only the matched operation template and the method are logged, never the request path or
	// query, which can carry user data.
	log := p.log.With("operation", op, "method", ds.Method)

	isLogin := op == p.cfg.loginPath
	switch {
	case isLogin:
		if ds.Method != http.MethodGet {
			log.Debug("OAuth2NativeSSO: skipped; the login path only signs in on GET")
			return pass // oauth2-session answers 405
		}
	case !p.cfg.transparentSSO:
		log.Debug("OAuth2NativeSSO: skipped; not the login path and transparentSso is off", "loginPath", p.cfg.loginPath)
		return pass
	case !isSafeRelativePath(ds.Path):
		log.Debug("OAuth2NativeSSO: skipped; the request path is not a safe redirect target")
		return pass // the 307 goes back to the request's own path; never redirect anywhere else
	}
	log.Debug("OAuth2NativeSSO: evaluating sign-in", "mode", map[bool]string{true: "login", false: "transparent"}[isLogin])

	has, why := p.hasTargetSession(ctx, ds.Headers, isLogin)
	if has {
		log.Debug("OAuth2NativeSSO: skipped; the request already has a target session", "detail", why)
		return pass
	}
	log.Debug("OAuth2NativeSSO: no usable target session", "detail", why)
	sourceSID, why := p.sourceSessionID(ds.Headers)
	if sourceSID == "" {
		log.Debug("OAuth2NativeSSO: skipped; no usable source session cookie", "cookie", p.cfg.source.cookieName, "detail", why)
		return pass
	}
	// From here on the request is tagged with a masked session reference: the first 8 hex digits of
	// the SHA3 hash that also names the session's Redis key, so a log line can be matched to
	// 'redis-cli --scan --pattern "*sess:<ref>*"' without logging the session ID itself.
	log = log.With("sourceSessionRef", maskedRef(sourceSID))
	log.Debug("OAuth2NativeSSO: source session cookie verified", "cookie", p.cfg.source.cookieName)
	scope := hashID(sourceSID + "\x00" + p.cfg.clientID + "\x00" + p.cfg.target.cookieName)

	if !isLogin {
		n, err := p.store.countRedirect(ctx, scope, handoffTTL)
		if err != nil {
			log.Warn("OAuth2NativeSSO: transparent sign-in skipped", "error", err)
			return pass
		}
		log.Debug("OAuth2NativeSSO: transparent redirect count", "count", n, "max", maxTransparentRedirects, "window", handoffTTL)
		if n > maxTransparentRedirects {
			log.Warn("OAuth2NativeSSO: transparent sign-in skipped; the browser keeps arriving without the target session cookie")
			return pass
		}
	}

	start := time.Now()
	cookie, err := p.signIn(ctx, log, sourceSID, scope)
	if err != nil {
		if errors.Is(err, errNoSSO) {
			log.Info("OAuth2NativeSSO: continuing without native sso", "reason", err, "elapsed", time.Since(start))
		} else {
			log.Warn("OAuth2NativeSSO: native sso failed; continuing without it", "error", err, "elapsed", time.Since(start))
		}
		return pass
	}

	if !isLogin {
		// 307 keeps the method and body; the browser repeats the request with the new cookie.
		log.Debug("OAuth2NativeSSO: answering 307 to the same path with the target session cookie", "elapsed", time.Since(start))
		return redirect(http.StatusTemporaryRedirect, ds.Path, cookie)
	}
	returnTo := p.cfg.postLoginRedirect
	returnToSource := "postLoginRedirect"
	if v := queryOf(ds.Path).Get("returnTo"); v != "" {
		if isSafeRelativePath(v) {
			returnTo, returnToSource = v, "returnTo"
		} else {
			returnToSource = "postLoginRedirect (returnTo rejected as unsafe)"
		}
	}
	log.Debug("OAuth2NativeSSO: answering 302 with the target session cookie", "location", returnToSource, "elapsed", time.Since(start))
	return redirect(http.StatusFound, returnTo, cookie)
}

// hasTargetSession reports whether the request already belongs to the target API. On the login
// path the cookie must verify and name a live session, otherwise an expired target session would
// block SSO; elsewhere the cookie's presence is enough, so ordinary API calls cost no Redis call.
// A Redis error counts as "has a session", leaving the request to oauth2-session. The second
// result says why, for debug logs; it never contains the cookie or session ID.
func (p *Policy) hasTargetSession(ctx context.Context, headers *policy.Headers, isLogin bool) (bool, string) {
	name := p.cfg.target.cookieName
	if !isLogin {
		if len(cookieValues(headers, name)) > 0 {
			return true, "target cookie " + name + " present"
		}
		return false, "target cookie " + name + " absent"
	}
	if why := cookieProblem(headers, name); why != "" {
		return false, "target " + why
	}
	value, _ := singleCookieValue(headers, name)
	sid, ok := verifySessionCookie(p.cfg.target.signingKey, value)
	if !ok {
		return false, "target cookie " + name + " has a bad signature or format"
	}
	exists, err := p.store.targetSessionExists(ctx, sid)
	if err != nil {
		p.log.Warn("OAuth2NativeSSO: could not check the target session", "error", err)
		return true, "target session check failed; leaving the request to oauth2-session"
	}
	if !exists {
		return false, "target cookie " + name + " verified but its session is gone from redis"
	}
	return true, "target cookie " + name + " names a live session"
}

// sourceSessionID returns the session ID of the request's single, correctly signed source cookie,
// or "" and the reason it is unusable.
func (p *Policy) sourceSessionID(headers *policy.Headers) (string, string) {
	name := p.cfg.source.cookieName
	if why := cookieProblem(headers, name); why != "" {
		return "", why
	}
	value, _ := singleCookieValue(headers, name)
	sid, ok := verifySessionCookie(p.cfg.source.signingKey, value)
	if !ok {
		return "", "cookie " + name + " has a bad signature or format (are source.sessionSigningKey and source.cookieName the source API's?)"
	}
	return sid, ""
}

// maskedRef is a short, non-reversible reference to a session ID for logs.
func maskedRef(sid string) string { return hashID(sid)[:8] }

// cookieProblem says why the request doesn't carry exactly one cookie called name, or "".
func cookieProblem(headers *policy.Headers, name string) string {
	switch n := len(cookieValues(headers, name)); n {
	case 0:
		return "cookie " + name + " absent"
	case 1:
		if _, ok := singleCookieValue(headers, name); !ok {
			return "cookie " + name + " unusable"
		}
		return ""
	default:
		return fmt.Sprintf("cookie %s sent %d times", name, n)
	}
}

// signIn returns the Set-Cookie of a target session for the source session sourceSID, creating
// the session with a Native SSO token exchange unless a concurrent request already has.
func (p *Policy) signIn(ctx context.Context, log *slog.Logger, sourceSID, scope string) (string, error) {
	if cookie, ok, err := p.fromHandoff(ctx, scope); err != nil || ok {
		if ok {
			log.Debug("OAuth2NativeSSO: reusing the target session a concurrent request created")
		}
		return cookie, err
	}

	src, err := p.store.loadSource(ctx, sourceSID)
	if err != nil {
		return "", err
	}
	if src == nil {
		return "", fmt.Errorf("%w: source session not found in redis (expired, logged out, or a different redis/keyPrefix)", errNoSSO)
	}
	now := p.now()
	sourceEnd := time.Unix(src.CreatedAt, 0).Add(p.cfg.source.absoluteSessionTimeout)
	log.Debug("OAuth2NativeSSO: source session loaded", "hasIdToken", src.IDToken != "",
		"hasDeviceSecret", src.DeviceSecret != "", "age", now.Sub(time.Unix(src.CreatedAt, 0)).Round(time.Second),
		"remaining", sourceEnd.Sub(now).Round(time.Second))
	if !now.Before(sourceEnd) {
		return "", fmt.Errorf("%w: source session reached its absolute timeout", errNoSSO)
	}
	switch {
	case src.IDToken == "" && src.DeviceSecret == "":
		return "", fmt.Errorf("%w: source session has no id_token and no device_secret", errNoSSO)
	case src.IDToken == "":
		return "", fmt.Errorf("%w: source session has no id_token", errNoSSO)
	case src.DeviceSecret == "":
		return "", fmt.Errorf("%w: source session has no device_secret (was the device_sso scope requested and granted at the source login?)", errNoSSO)
	}

	token, acquired, err := p.store.acquireLock(ctx, scope, p.lockTTL)
	if err != nil {
		return "", err
	}
	if !acquired {
		log.Debug("OAuth2NativeSSO: another request is exchanging for this browser; waiting for its result")
		return p.waitForHandoff(ctx, scope)
	}
	log.Debug("OAuth2NativeSSO: exchange lock acquired", "lockTtl", p.lockTTL)
	defer func() {
		if err := p.store.releaseLock(context.WithoutCancel(ctx), scope, token); err != nil {
			log.Warn("OAuth2NativeSSO: releasing the sso lock failed", "error", err)
		}
	}()
	// Another replica may have finished between the first handoff check and taking the lock.
	if cookie, ok, err := p.fromHandoff(ctx, scope); err != nil || ok {
		if ok {
			log.Debug("OAuth2NativeSSO: a concurrent request finished first; reusing its target session")
		}
		return cookie, err
	}

	exStart := time.Now()
	tok, err := p.tokens.exchange(ctx, src.IDToken, src.DeviceSecret)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	log.Debug("OAuth2NativeSSO: token exchange succeeded", "elapsed", time.Since(exStart),
		"tokenType", tok.TokenType, "expiresIn", tok.Expiry.Sub(now).Round(time.Second), "grantedScopes", tok.Scopes,
		"hasRefreshToken", tok.RefreshToken != "", "hasIdToken", tok.IDToken != "",
		"deviceSecretRotated", tok.DeviceSecret != "" && tok.DeviceSecret != src.DeviceSecret)
	indexKeys, err := p.checkIDToken(log, tok.IDToken, src.IDToken)
	if err != nil {
		return "", err
	}

	// The target session never outlives the source: its login time is moved back so that the
	// target's own absolute timeout ends it no later than the source's.
	createdAt := now.Unix()
	if capped := sourceEnd.Add(-p.cfg.target.absoluteSessionTimeout).Unix(); capped < createdAt {
		createdAt = capped
	}
	remaining := time.Unix(createdAt, 0).Add(p.cfg.target.absoluteSessionTimeout).Sub(now)
	if remaining < time.Second {
		return "", fmt.Errorf("%w: source session is about to expire", errNoSSO)
	}
	ttl := min(p.cfg.target.idleTimeout, remaining)

	deviceSecret := src.DeviceSecret
	if tok.DeviceSecret != "" {
		deviceSecret = tok.DeviceSecret
	}
	sid, err := newRandomID()
	if err != nil {
		return "", err
	}
	sess := &targetSession{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		IDToken:      tok.IDToken,
		Scopes:       tok.Scopes,
		ExpiresAt:    tok.Expiry.Unix(),
		CreatedAt:    createdAt,
		ObtainedAt:   now.Unix(),
		DeviceSecret: deviceSecret,
	}
	if err := p.store.createTarget(ctx, sid, sess, ttl, indexKeys, p.cfg.target.absoluteSessionTimeout, scope, handoffTTL); err != nil {
		return "", err
	}
	log.Debug("OAuth2NativeSSO: target session stored", "targetSessionRef", maskedRef(sid), "idleTtl", ttl.Round(time.Second),
		"absoluteRemaining", remaining.Round(time.Second), "cappedBySource", createdAt != now.Unix(),
		"backchannelIndexes", len(indexKeys))

	// The IdP rotated the device_secret: the source must use the new one from now on.
	if deviceSecret != src.DeviceSecret {
		changed, err := p.store.rotateSourceDeviceSecret(ctx, sourceSID, src.DeviceSecret, deviceSecret)
		if err != nil {
			log.Warn("OAuth2NativeSSO: storing the rotated device_secret in the source session failed", "error", err)
		} else {
			log.Debug("OAuth2NativeSSO: rotated device_secret written back to the source session", "written", changed)
		}
	}
	log.Info("OAuth2NativeSSO: signed in to the target API with native sso", "clientId", p.cfg.clientID)
	return p.targetCookie(sid, createdAt), nil
}

// checkIDToken validates the id_token of the exchange when an issuer is configured: it must come
// from the issuer, be issued to this client and belong to the same IdP session as the source's.
// It returns the back-channel logout index sets the new session joins.
func (p *Policy) checkIDToken(log *slog.Logger, idToken, sourceIDToken string) ([]string, error) {
	if p.cfg.issuer == "" {
		log.Debug("OAuth2NativeSSO: id_token checks skipped; no issuer configured")
		return nil, nil
	}
	if idToken == "" {
		return nil, errors.New("token exchange response has no id_token")
	}
	claims, err := parseIDTokenClaims(idToken)
	if err != nil {
		return nil, err
	}
	issuerOK, audienceOK := claims.Iss == p.cfg.issuer, claims.hasAudience(p.cfg.clientID)
	srcClaims, srcErr := parseIDTokenClaims(sourceIDToken)
	sourceHasSid := srcErr == nil && srcClaims.Sid != ""
	log.Debug("OAuth2NativeSSO: checking the exchanged id_token", "issuerMatches", issuerOK, "audienceMatches", audienceOK,
		"sourceHasSid", sourceHasSid, "targetHasSid", claims.Sid != "", "sidMatches", sourceHasSid && claims.Sid == srcClaims.Sid)
	if !issuerOK || !audienceOK {
		return nil, errors.New("id_token issuer or audience does not match the configuration")
	}
	if sourceHasSid && claims.Sid != srcClaims.Sid {
		return nil, errors.New("id_token belongs to a different identity provider session")
	}
	var keys []string
	if claims.Sid != "" {
		keys = append(keys, p.store.idpIndexKey("sid", claims.Iss, claims.Sid))
	}
	if claims.Sub != "" {
		keys = append(keys, p.store.idpIndexKey("sub", claims.Iss, claims.Sub))
	}
	return keys, nil
}

// fromHandoff returns the cookie of a target session a concurrent request created, if that
// session is still alive.
func (p *Policy) fromHandoff(ctx context.Context, scope string) (string, bool, error) {
	h, err := p.store.readHandoff(ctx, scope)
	if err != nil || h == nil {
		return "", false, err
	}
	exists, err := p.store.targetSessionExists(ctx, h.SID)
	if err != nil || !exists {
		return "", false, err
	}
	return p.targetCookie(h.SID, h.CreatedAt), true, nil
}

// waitForHandoff waits for the request holding the exchange lock, then takes its result.
func (p *Policy) waitForHandoff(ctx context.Context, scope string) (string, error) {
	deadline := time.Now().Add(p.lockTTL)
	timer := time.NewTimer(lockPollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
		}
		held, err := p.store.lockHeld(ctx, scope)
		if err != nil {
			return "", err
		}
		if !held || time.Now().After(deadline) {
			break
		}
		timer.Reset(lockPollInterval)
	}
	cookie, ok, err := p.fromHandoff(ctx, scope)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: concurrent exchange did not create a session", errNoSSO)
	}
	return cookie, nil
}

// targetCookie builds the target's Set-Cookie, living as long as the session's absolute lifetime -
// exactly what the target's oauth2-session would issue for it.
func (p *Policy) targetCookie(sid string, createdAt int64) string {
	t := p.cfg.target
	maxAge := time.Unix(createdAt, 0).Add(t.absoluteSessionTimeout).Sub(p.now())
	return buildSetCookie(t.cookieName, sessionCookieValue(t.signingKey, sid), maxAge, t.cookieSameSite, t.cookieSecure)
}

// redirect answers with a redirect that sets one cookie. It must never be cached.
func redirect(status int, location, setCookie string) policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: status,
		Headers: map[string]string{
			"location":      location,
			"set-cookie":    setCookie,
			"cache-control": "no-store",
		},
	}
}
