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
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// metadataKeySetCookie carries a re-issued session cookie from the request phase to
	// OnResponseHeaders, where it is appended to the backend's response.
	metadataKeySetCookie = "oauth2-session.set-cookie"

	// metadataKeyUpstreamToken carries an upstreamTokenRef from the request phase to
	// OnResponseHeaders, so a 401 from the backend can mark that access token as expired.
	metadataKeyUpstreamToken = "oauth2-session.upstream-token"
)

// ProxyPolicy is the oauth2-session-proxy policy: it turns the session cookie set by
// oauth2-session into a bearer token on the request sent to the backend. It reads the same Redis
// records with the same keys, so it must be configured with the same client, cookie and keys as
// the oauth2-session attachment that logs users in.
type ProxyPolicy struct {
	*Policy
}

// NewProxyPolicy builds an oauth2-session-proxy attachment. It is exported for the
// oauth2-session-proxy module, which only wraps it.
func NewProxyPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (*ProxyPolicy, error) {
	cfg, err := parseProxyConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	p, err := newPolicyFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	slog.Debug("OAuth2SessionProxy: policy initialized", "route", metadata.RouteName,
		"clientId", cfg.clientID, "upstreamHeaderName", cfg.upstreamHeaderName, "continueWithoutCookie", cfg.continueWithoutCookie)
	return &ProxyPolicy{Policy: p}, nil
}

// Mode processes request headers (authentication) and response headers (to re-issue the session
// cookie after a refresh and to notice a backend 401). Bodies are never buffered, so it suits
// streaming and proxied traffic.
func (p *ProxyPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders authenticates every request it sees, whatever the operation path: the
// operations it is attached to are the protected ones.
func (p *ProxyPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	return p.handleProtected(ctx, reqCtx)
}

// upstreamTokenRef identifies the access token sent to the backend: the session's Redis key and a
// SHA3-256 hash of the token. Neither can be used as a cookie or a bearer token.
type upstreamTokenRef struct {
	sessionKey string
	tokenHash  string
}

// OnResponseHeaders appends the session cookie re-issued during a refresh. It is appended rather
// than set so a Set-Cookie from the backend is kept. When the backend answered 401, the access
// token it rejected is marked as expired so the next request refreshes it.
func (p *ProxyPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if respCtx.SharedContext == nil {
		return nil
	}
	if ref, ok := respCtx.Metadata[metadataKeyUpstreamToken].(upstreamTokenRef); ok && upstreamStatus(respCtx) == http.StatusUnauthorized {
		p.expireRejectedToken(ctx, ref)
	}
	cookie, ok := respCtx.Metadata[metadataKeySetCookie].(string)
	if !ok || cookie == "" {
		return nil
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToAppend: map[string][]string{"set-cookie": {cookie}},
	}
}

// upstreamStatus is the status the backend sent, before any policy changed the response.
func upstreamStatus(respCtx *policy.ResponseHeaderContext) int {
	if respCtx.Upstream != nil && respCtx.Upstream.Response != nil {
		return respCtx.Upstream.Response.StatusCode
	}
	return respCtx.ResponseStatus
}

// expireRejectedToken marks an access token the backend rejected as expired. The client still
// gets this 401; its next request refreshes the token if the refresh token is valid, or ends the
// session if there is none. Failure only means no early refresh, so it is logged, not returned.
func (p *ProxyPolicy) expireRejectedToken(ctx context.Context, ref upstreamTokenRef) {
	marked, err := p.store.expireAccessToken(ctx, ref.sessionKey, ref.tokenHash)
	if err != nil {
		slog.Warn("OAuth2SessionProxy: marking the rejected access token as expired failed", "error", err)
		return
	}
	if marked {
		slog.Info("OAuth2SessionProxy: backend rejected the access token; it will be refreshed on the next request")
	}
}

// handleProtected authenticates an API call from its session cookie, adds the bearer token for
// the backend, and removes this policy's cookies from the request sent upstream.
func (p *ProxyPolicy) handleProtected(ctx context.Context, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	shared := reqCtx.SharedContext

	// With continueWithoutCookie, a request that carries no session cookie at all isn't this
	// policy's to judge: it continues unchanged to the next policies (for example a JWT or API key
	// policy for non-browser clients), and the AuthContext is left as it was. A request that does
	// carry the cookie is still authenticated here, and rejected if its session isn't valid.
	if p.cfg.continueWithoutCookie && len(cookieValues(reqCtx.DownstreamHeaders(), p.cfg.cookieName)) == 0 {
		slog.Debug("OAuth2SessionProxy: no session cookie; continuing to the next policies")
		return policy.UpstreamRequestHeaderModifications{}
	}

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
		slog.Error("OAuth2SessionProxy: session check failed", "error", err)
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
	// A token younger than the cooldown is not marked on a backend 401, so a backend that rejects
	// every token can't turn each request into a refresh.
	if p.cfg.refreshOnUpstreamUnauthorized && shared != nil &&
		!p.now().Before(sess.obtained().Add(p.cfg.upstreamUnauthorizedCooldown)) {
		if shared.Metadata == nil {
			shared.Metadata = map[string]interface{}{}
		}
		shared.Metadata[metadataKeyUpstreamToken] = upstreamTokenRef{
			sessionKey: p.store.sessionKey(sid),
			tokenHash:  hashID(sess.AccessToken),
		}
	}

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
