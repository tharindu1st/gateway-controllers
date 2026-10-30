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

// Package oauth2session implements a browser login session on top of the gateway.
//
// The gateway acts as a confidential OAuth 2.0 client using the authorization code grant. The
// browser only ever holds an opaque, signed session cookie; access and refresh tokens are kept
// encrypted in Redis, refreshed shortly before they expire, and sent to the backend as a bearer
// token. The policy answers the login, callback and logout operations itself and protects every
// other operation of the API it is attached to.
package oauth2session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType is the AuthContext.AuthType this policy records.
	AuthType = "oauth2-session"

	// metadataKeySetCookie carries a re-issued session cookie from the request phase to
	// OnResponseHeaders, where it is appended to the backend's response.
	metadataKeySetCookie = "oauth2-session.set-cookie"

	// refreshLockPollInterval is how often a request waiting on another request's refresh
	// re-checks the lock.
	refreshLockPollInterval = 50 * time.Millisecond
)

// errNoSession means the request has no usable session: no cookie, a forged or malformed cookie,
// an unknown, expired or revoked session, or a refresh token the IdP rejected.
var errNoSession = errors.New("no valid session")

// Policy is one oauth2-session attachment.
type Policy struct {
	cfg     *config
	store   *sessionStore
	tokens  *tokenClient
	now     func() time.Time
	lockTTL time.Duration
}

// GetPolicy is the v1alpha2 factory entry point. Configuration errors surface here, at deploy
// time, rather than per request.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// The ping result is ignored: an unreachable Redis fails each request closed at first use.
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

	store, err := newSessionStore(client, cfg.redis, cfg.encryptionKey)
	if err != nil {
		return nil, err
	}
	tokens, err := newTokenClient(cfg)
	if err != nil {
		return nil, err
	}

	slog.Debug("OAuth2Session: policy initialized", "route", metadata.RouteName,
		"clientId", cfg.clientID, "loginPath", cfg.loginPath, "callbackPath", cfg.callbackPath, "logoutPath", cfg.logoutPath)
	return newPolicy(cfg, store, tokens), nil
}

func newPolicy(cfg *config, store *sessionStore, tokens *tokenClient) *Policy {
	retries := time.Duration(cfg.tokenRequestMaxRetries)
	return &Policy{
		cfg:    cfg,
		store:  store,
		tokens: tokens,
		now:    time.Now,
		// Long enough to cover a refresh with all its retries, so the lock outlives the request
		// that holds it; the jittered backoff can reach 1.5x retryMaxDelay.
		lockTTL: cfg.tokenRequestTimeout*(retries+1) + 3*retryMaxDelay/2*retries + time.Second,
	}
}

// Mode processes request headers (all routing and authentication) and response headers (to
// re-issue the session cookie after a refresh). Bodies are never buffered.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders dispatches on the operation path the router matched, never on the raw
// request path, so encoded or dot-segment tricks can't turn a protected request into a login one.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	op := ""
	if reqCtx.SharedContext != nil {
		op = reqCtx.OperationPath
	}
	ds := reqCtx.DownstreamRequest()

	switch op {
	case p.cfg.loginPath, p.cfg.callbackPath, p.cfg.logoutPath:
		if ds.Method != http.MethodGet {
			return methodNotAllowed()
		}
	}

	switch op {
	case p.cfg.loginPath:
		return p.handleLogin(ctx, ds)
	case p.cfg.callbackPath:
		return p.handleCallback(ctx, ds)
	case p.cfg.logoutPath:
		return p.handleLogout(ctx, ds)
	default:
		return p.handleProtected(ctx, reqCtx)
	}
}

// OnResponseHeaders appends the session cookie re-issued during a refresh. It is appended rather
// than set so a Set-Cookie from the backend is kept.
func (p *Policy) OnResponseHeaders(_ context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if respCtx.SharedContext == nil {
		return nil
	}
	cookie, ok := respCtx.Metadata[metadataKeySetCookie].(string)
	if !ok || cookie == "" {
		return nil
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToAppend: map[string][]string{"set-cookie": {cookie}},
	}
}

// handleLogin returns a user with a valid session to returnTo, refreshing first if the access
// token is about to expire. Anyone else is sent to the authorization endpoint.
func (p *Policy) handleLogin(ctx context.Context, ds *policy.DownstreamRequest) policy.RequestHeaderAction {
	returnTo := p.cfg.postLoginRedirect
	if v := queryOf(ds.Path).Get("returnTo"); v != "" {
		if isSafeRelativePath(v) {
			returnTo = v
		} else {
			slog.Debug("OAuth2Session: ignoring unsafe returnTo")
		}
	}

	sid, sess, err := p.currentSession(ctx, ds.Headers)
	if err == nil {
		sess, _, err = p.ensureFresh(ctx, sid, sess)
		if err == nil {
			return redirect(returnTo, p.sessionCookie(sid, sess))
		}
	}
	if !errors.Is(err, errNoSession) {
		slog.Error("OAuth2Session: login could not check the existing session", "error", err)
		return unavailable()
	}
	return p.startLogin(ctx, returnTo)
}

// startLogin records a pending login and redirects to the authorization endpoint.
func (p *Policy) startLogin(ctx context.Context, returnTo string) policy.RequestHeaderAction {
	state, err := newRandomID()
	if err != nil {
		slog.Error("OAuth2Session: generating login state failed", "error", err)
		return unavailable()
	}
	if err := p.store.saveState(ctx, state, returnTo, p.cfg.stateTTL); err != nil {
		slog.Error("OAuth2Session: storing login state failed", "error", err)
		return unavailable()
	}
	// The state cookie is always SameSite=Lax: the IdP's redirect back to the callback is a
	// cross-site navigation, and a Strict cookie would not be sent with it.
	stateCookie := buildSetCookie(p.cfg.stateCookieName, state, p.cfg.stateTTL, SameSiteLax, p.cfg.cookieSecure)
	return redirect(p.authorizationURL(state), stateCookie)
}

// authorizationURL builds the authorization request (RFC 6749 §4.1.1) from configuration only.
// Query parameters already on authorizationEndpoint are kept.
func (p *Policy) authorizationURL(state string) string {
	u, _ := url.Parse(p.cfg.authorizationEndpoint) // validated in parseConfig
	q := u.Query()
	for k, v := range p.cfg.authorizationRequestParams {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.clientID)
	q.Set("redirect_uri", p.cfg.redirectURI)
	if len(p.cfg.scopes) > 0 {
		q.Set("scope", strings.Join(p.cfg.scopes, " "))
	}
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// handleCallback completes a login: it checks state against the browser's state cookie and the
// single-use Redis record, redeems the code, and creates a brand-new session.
func (p *Policy) handleCallback(ctx context.Context, ds *policy.DownstreamRequest) policy.RequestHeaderAction {
	q := queryOf(ds.Path)
	state := q.Get("state")
	cookieState, ok := singleCookieValue(ds.Headers, p.cfg.stateCookieName)
	if state == "" || !ok || !constantTimeEqual(state, cookieState) {
		slog.Warn("OAuth2Session: callback rejected", "reason", "state missing or does not match the state cookie")
		return unauthorized()
	}

	returnTo, found, err := p.store.takeState(ctx, state)
	if err != nil {
		slog.Error("OAuth2Session: reading login state failed", "error", err)
		return unavailable()
	}
	if !found {
		slog.Warn("OAuth2Session: callback rejected", "reason", "state unknown, expired or already used")
		return unauthorized()
	}

	if idpErr := q.Get("error"); idpErr != "" {
		slog.Warn("OAuth2Session: callback rejected", "reason", "identity provider returned an error",
			"idpError", sanitizeErrorCode(idpErr))
		return unauthorized()
	}
	code := q.Get("code")
	if code == "" {
		slog.Warn("OAuth2Session: callback rejected", "reason", "authorization code missing")
		return unauthorized()
	}

	tok, err := p.tokens.exchangeCode(ctx, code)
	if err != nil {
		if isRejection(err) {
			slog.Warn("OAuth2Session: callback rejected", "reason", "code exchange rejected", "error", err)
			return unauthorized()
		}
		slog.Error("OAuth2Session: code exchange failed", "error", err)
		return unavailable()
	}

	indexKeys, ok := p.backchannelIndexKeys(tok.IDToken)
	if !ok {
		return unauthorized()
	}

	// A new ID on every login: an ID the browser already had is never adopted (session fixation).
	sid, err := newRandomID()
	if err != nil {
		slog.Error("OAuth2Session: generating session id failed", "error", err)
		return unavailable()
	}
	now := p.now()
	sess := &session{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		IDToken:      tok.IDToken,
		Scopes:       tok.Scopes,
		ExpiresAt:    tok.Expiry.Unix(),
		CreatedAt:    now.Unix(),
	}
	if err := p.store.createSession(ctx, sid, sess, p.sessionTTL(sess, now), indexKeys, p.cfg.absoluteSessionTimeout); err != nil {
		slog.Error("OAuth2Session: storing session failed", "error", err)
		return unavailable()
	}

	// Best effort: end the session this browser had before, so it doesn't linger until expiry.
	if old, ok := singleCookieValue(ds.Headers, p.cfg.cookieName); ok {
		if oldSID, ok := verifySessionCookie(p.cfg.signingKey, old); ok {
			if err := p.store.deleteSession(ctx, oldSID); err != nil {
				slog.Warn("OAuth2Session: removing the previous session failed", "error", err)
			}
		}
	}

	if !isSafeRelativePath(returnTo) {
		returnTo = p.cfg.postLoginRedirect
	}
	return redirect(returnTo, p.sessionCookie(sid, sess))
}

// backchannelIndexKeys returns the identity provider index sets a new session joins, so that
// oauth2-session-backchannel-logout can find it by the IdP's sid or sub. With no issuer
// configured there is no index. ok is false when the id_token names a different issuer or
// audience, which fails the login.
func (p *Policy) backchannelIndexKeys(idToken string) (keys []string, ok bool) {
	if p.cfg.issuer == "" {
		return nil, true
	}
	if idToken == "" {
		slog.Warn("OAuth2Session: token response has no id_token; back-channel logout won't find this session (is the openid scope requested?)")
		return nil, true
	}
	claims, err := parseIDTokenClaims(idToken)
	if err != nil {
		slog.Warn("OAuth2Session: callback rejected", "reason", "id_token could not be decoded", "error", err)
		return nil, false
	}
	if claims.Iss != p.cfg.issuer || !claims.hasAudience(p.cfg.clientID) {
		slog.Warn("OAuth2Session: callback rejected", "reason", "id_token issuer or audience does not match the configuration")
		return nil, false
	}
	if claims.Sid != "" {
		keys = append(keys, p.store.idpIndexKey("sid", claims.Iss, claims.Sid))
	}
	if claims.Sub != "" {
		keys = append(keys, p.store.idpIndexKey("sub", claims.Iss, claims.Sub))
	}
	return keys, true
}

// handleLogout deletes the session and clears the cookie. If the session can't be deleted the
// response says so (503) instead of reporting a logout that didn't happen.
func (p *Policy) handleLogout(ctx context.Context, ds *policy.DownstreamRequest) policy.RequestHeaderAction {
	clearCookie := buildSetCookie(p.cfg.cookieName, "", 0, p.cfg.cookieSameSite, p.cfg.cookieSecure)
	idToken := ""

	if value, ok := singleCookieValue(ds.Headers, p.cfg.cookieName); ok {
		if sid, ok := verifySessionCookie(p.cfg.signingKey, value); ok {
			if p.cfg.endSessionEndpoint != "" {
				if sess, err := p.store.getSession(ctx, sid); err == nil && sess != nil {
					idToken = sess.IDToken
				}
			}
			if err := p.store.deleteSession(ctx, sid); err != nil {
				slog.Error("OAuth2Session: deleting session on logout failed", "error", err)
				resp := unavailable()
				resp.Headers["set-cookie"] = clearCookie
				return resp
			}
		}
	}

	location := p.cfg.postLogoutRedirect
	if p.cfg.endSessionEndpoint != "" {
		location = p.endSessionURL(idToken)
	}
	return redirect(location, clearCookie)
}

// endSessionURL builds the IdP logout redirect (OpenID Connect RP-Initiated Logout). The
// post-logout URL is made absolute from redirectUri's origin, since IdPs require absolute URLs.
func (p *Policy) endSessionURL(idToken string) string {
	u, _ := url.Parse(p.cfg.endSessionEndpoint) // validated in parseConfig
	origin, _ := url.Parse(p.cfg.redirectURI)
	postLogout := &url.URL{Scheme: origin.Scheme, Host: origin.Host}
	q := u.Query()
	q.Set("client_id", p.cfg.clientID)
	q.Set("post_logout_redirect_uri", postLogout.String()+p.cfg.postLogoutRedirect)
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// handleProtected authenticates an API call from its session cookie, adds the bearer token for
// the backend, and removes this policy's cookies from the request sent upstream.
func (p *Policy) handleProtected(ctx context.Context, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	shared := reqCtx.SharedContext

	sid, sess, err := p.currentSession(ctx, reqCtx.DownstreamHeaders())
	refreshed := false
	if err == nil {
		sess, refreshed, err = p.ensureFresh(ctx, sid, sess)
	}
	if errors.Is(err, errNoSession) {
		p.recordAuth(shared, nil)
		return unauthorized()
	}
	if err != nil {
		slog.Error("OAuth2Session: session check failed", "error", err)
		p.recordAuth(shared, nil)
		return unavailable()
	}

	if refreshed && shared != nil {
		if shared.Metadata == nil {
			shared.Metadata = map[string]interface{}{}
		}
		shared.Metadata[metadataKeySetCookie] = p.sessionCookie(sid, sess)
	}
	p.recordAuth(shared, sess)

	value := sess.AccessToken
	if p.cfg.upstreamValuePrefix != "" {
		value = p.cfg.upstreamValuePrefix + " " + value
	}
	mods := policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{p.cfg.upstreamHeaderName: value},
	}
	// The live header set is rewritten (not the downstream snapshot) because the result replaces
	// the Cookie header forwarded upstream.
	if reqCtx.Headers != nil {
		if remaining, removed := stripCookies(reqCtx.Headers.Get("cookie"), p.cfg.cookieName, p.cfg.stateCookieName); removed {
			if remaining == "" {
				mods.HeadersToRemove = []string{"cookie"}
			} else {
				mods.HeadersToSet["cookie"] = remaining
			}
		}
	}
	return mods
}

// currentSession resolves the request's session cookie to a live session, sliding its idle
// timeout. Forged or malformed cookies are rejected before Redis is touched. A non-errNoSession
// error means Redis itself failed.
func (p *Policy) currentSession(ctx context.Context, headers *policy.Headers) (string, *session, error) {
	value, ok := singleCookieValue(headers, p.cfg.cookieName)
	if !ok {
		return "", nil, errNoSession
	}
	sid, ok := verifySessionCookie(p.cfg.signingKey, value)
	if !ok {
		slog.Debug("OAuth2Session: session cookie failed verification")
		return "", nil, errNoSession
	}
	sess, err := p.store.loadSession(ctx, sid, p.cfg.idleTimeout)
	if err != nil {
		return "", nil, err
	}
	if sess == nil {
		return "", nil, errNoSession
	}
	if !p.now().Before(sess.created().Add(p.cfg.absoluteSessionTimeout)) {
		p.dropSession(ctx, sid, "absolute session timeout reached")
		return "", nil, errNoSession
	}
	return sid, sess, nil
}

// ensureFresh returns a session whose access token is usable, refreshing it when it expires
// within refreshBuffer. refreshed is true when this request stored new tokens.
func (p *Policy) ensureFresh(ctx context.Context, sid string, sess *session) (*session, bool, error) {
	now := p.now()
	if now.Add(p.cfg.refreshBuffer).Before(sess.expiry()) {
		return sess, false, nil
	}
	if sess.RefreshToken == "" {
		if now.Before(sess.expiry()) {
			return sess, false, nil
		}
		p.dropSession(ctx, sid, "access token expired and there is no refresh token")
		return nil, false, errNoSession
	}

	lockToken, acquired, err := p.store.acquireRefreshLock(ctx, sid, p.lockTTL)
	if err != nil {
		return nil, false, err
	}
	if !acquired {
		// Another request is refreshing. A token that hasn't expired yet is still good to use.
		if now.Before(sess.expiry()) {
			return sess, false, nil
		}
		return p.waitForRefresh(ctx, sid)
	}
	defer func() {
		if err := p.store.releaseRefreshLock(context.WithoutCancel(ctx), sid, lockToken); err != nil {
			slog.Warn("OAuth2Session: releasing refresh lock failed", "error", err)
		}
	}()

	// Another request may have refreshed between our read and taking the lock.
	latest, err := p.store.getSession(ctx, sid)
	if err != nil {
		return nil, false, err
	}
	if latest == nil {
		return nil, false, errNoSession
	}
	if now.Add(p.cfg.refreshBuffer).Before(latest.expiry()) {
		return latest, false, nil
	}

	tok, err := p.tokens.refresh(ctx, latest.RefreshToken)
	if err != nil {
		if isRejection(err) {
			p.dropSession(ctx, sid, "refresh token rejected: "+err.Error())
			return nil, false, errNoSession
		}
		if now.Before(latest.expiry()) {
			// Transient IdP failure: keep using the current token; the next request retries.
			slog.Warn("OAuth2Session: token refresh failed, using the current access token", "error", err)
			return latest, false, nil
		}
		return nil, false, fmt.Errorf("refreshing access token: %w", err)
	}

	updated := &session{
		AccessToken:  tok.AccessToken,
		RefreshToken: firstNonEmpty(tok.RefreshToken, latest.RefreshToken), // IdPs that don't rotate omit it
		TokenType:    tok.TokenType,
		IDToken:      firstNonEmpty(tok.IDToken, latest.IDToken),
		Scopes:       latest.Scopes,
		ExpiresAt:    tok.Expiry.Unix(),
		CreatedAt:    latest.CreatedAt,
	}
	if len(tok.Scopes) > 0 {
		updated.Scopes = tok.Scopes
	}
	stored, err := p.store.updateSession(ctx, sid, updated, p.sessionTTL(updated, now))
	if err != nil {
		// The new token is still valid for this request; a later request will refresh again.
		slog.Error("OAuth2Session: storing refreshed session failed", "error", err)
		return updated, true, nil
	}
	if !stored {
		// The session was ended (for example by back-channel logout) while refreshing.
		return nil, false, errNoSession
	}
	return updated, true, nil
}

// waitForRefresh waits for the request holding the refresh lock to finish, then re-reads the
// session. It is only reached when this request's own access token has already expired.
func (p *Policy) waitForRefresh(ctx context.Context, sid string) (*session, bool, error) {
	deadline := time.Now().Add(p.lockTTL)
	timer := time.NewTimer(refreshLockPollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-timer.C:
		}
		held, err := p.store.refreshLockHeld(ctx, sid)
		if err != nil {
			return nil, false, err
		}
		if !held || time.Now().After(deadline) {
			break
		}
		timer.Reset(refreshLockPollInterval)
	}

	latest, err := p.store.getSession(ctx, sid)
	if err != nil {
		return nil, false, err
	}
	if latest == nil {
		return nil, false, errNoSession // the other request's refresh was rejected
	}
	if p.now().Before(latest.expiry()) {
		return latest, false, nil
	}
	return nil, false, fmt.Errorf("concurrent refresh did not produce a usable access token")
}

// dropSession deletes a session that can no longer be used. Failure only leaves a dead record
// behind until its TTL, so it is logged, not returned.
func (p *Policy) dropSession(ctx context.Context, sid, reason string) {
	slog.Info("OAuth2Session: ending session", "reason", reason)
	if err := p.store.deleteSession(ctx, sid); err != nil {
		slog.Warn("OAuth2Session: deleting session failed", "error", err)
	}
}

// sessionTTL is the Redis lifetime of a session record: the idle timeout, capped by what is left
// of the absolute session lifetime.
func (p *Policy) sessionTTL(sess *session, now time.Time) time.Duration {
	remaining := sess.created().Add(p.cfg.absoluteSessionTimeout).Sub(now)
	if remaining < p.cfg.idleTimeout {
		return remaining
	}
	return p.cfg.idleTimeout
}

// sessionCookie builds the Set-Cookie for sid. The cookie lives as long as the session's absolute
// lifetime; the idle timeout is enforced in Redis, so the cookie needn't be re-sent on every request.
func (p *Policy) sessionCookie(sid string, sess *session) string {
	maxAge := sess.created().Add(p.cfg.absoluteSessionTimeout).Sub(p.now())
	return buildSetCookie(p.cfg.cookieName, sessionCookieValue(p.cfg.signingKey, sid), maxAge, p.cfg.cookieSameSite, p.cfg.cookieSecure)
}

// recordAuth stores the authentication result in the shared AuthContext, preserving any chain.
func (p *Policy) recordAuth(shared *policy.SharedContext, sess *session) {
	if shared == nil {
		return
	}
	ac := &policy.AuthContext{
		Authenticated: sess != nil,
		AuthType:      AuthType,
		CredentialID:  p.cfg.clientID,
		Previous:      shared.AuthContext,
	}
	if sess != nil && len(sess.Scopes) > 0 {
		ac.Scopes = make(map[string]bool, len(sess.Scopes))
		for _, s := range sess.Scopes {
			ac.Scopes[s] = true
		}
	}
	shared.AuthContext = ac
}

// queryOf parses the query string of a :path value.
func queryOf(path string) url.Values {
	idx := strings.IndexByte(path, '?')
	if idx < 0 {
		return url.Values{}
	}
	q, _ := url.ParseQuery(path[idx+1:]) // keeps whatever parsed; bad pairs are dropped
	return q
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// redirect is a 302 that sets one cookie. Responses carrying cookies must never be cached.
func redirect(location, setCookie string) policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: http.StatusFound,
		Headers: map[string]string{
			"location":      location,
			"set-cookie":    setCookie,
			"cache-control": "no-store",
		},
	}
}

// unauthorized is the single response for every authentication failure, whatever the reason.
func unauthorized() policy.ImmediateResponse {
	return jsonResponse(http.StatusUnauthorized, "unauthorized", "Invalid or expired credentials.")
}

// unavailable is returned when Redis or the identity provider can't be reached.
func unavailable() policy.ImmediateResponse {
	return jsonResponse(http.StatusServiceUnavailable, "service_unavailable", "The service is temporarily unavailable. Try again later.")
}

func methodNotAllowed() policy.ImmediateResponse {
	resp := jsonResponse(http.StatusMethodNotAllowed, "method_not_allowed", "Use GET for this route.")
	resp.Headers["allow"] = http.MethodGet
	return resp
}

func jsonResponse(status int, code, message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": code, "message": message})
	return policy.ImmediateResponse{
		StatusCode: status,
		Headers: map[string]string{
			"content-type":  "application/json",
			"cache-control": "no-store",
		},
		Body: body,
	}
}
