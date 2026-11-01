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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// fakeIdP is a token endpoint that accepts one authorization code and rotates refresh tokens.
type fakeIdP struct {
	srv           *httptest.Server
	refreshCalls  atomic.Int32
	refreshDelay  time.Duration
	onRefresh     func()       // runs while a refresh request is being served
	refreshStatus atomic.Int32 // non-zero forces this status on refresh
	rotateDevice  atomic.Bool  // refresh responses carry a new device_secret
	mu            sync.Mutex
	validRefresh  map[string]int // refresh token -> generation of the tokens it yields
}

func newFakeIdP(t *testing.T) *fakeIdP {
	idp := &fakeIdP{validRefresh: map[string]int{}}
	idp.srv = httptest.NewServer(http.HandlerFunc(idp.serveToken))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "orders-web" || pass != "client-secret" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	_ = r.ParseForm()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if r.PostForm.Get("code") != "good-code" || r.PostForm.Get("redirect_uri") != "https://gw.example.com/orders/v1/callback" {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		idp.issue(w, 1, true)
	case "refresh_token":
		idp.refreshCalls.Add(1)
		time.Sleep(idp.refreshDelay)
		if idp.onRefresh != nil {
			idp.onRefresh()
		}
		if s := idp.refreshStatus.Load(); s != 0 {
			writeTokenError(w, int(s), "server_error")
			return
		}
		idp.mu.Lock()
		gen, ok := idp.validRefresh[r.PostForm.Get("refresh_token")]
		delete(idp.validRefresh, r.PostForm.Get("refresh_token")) // rotation: each refresh token works once
		idp.mu.Unlock()
		if !ok {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		idp.issue(w, gen+1, idp.rotateDevice.Load())
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (idp *fakeIdP) issue(w http.ResponseWriter, gen int, deviceSecret bool) {
	rt := "rt-" + strconv.Itoa(gen)
	idp.mu.Lock()
	idp.validRefresh[rt] = gen
	idp.mu.Unlock()
	resp := map[string]interface{}{
		"access_token":  "at-" + strconv.Itoa(gen),
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid orders:read",
		"id_token":      testIDToken(gen),
	}
	if deviceSecret {
		resp["device_secret"] = "ds-" + strconv.Itoa(gen)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// testIDToken is a JWT-shaped id_token. Its signature is a placeholder: oauth2-session only
// decodes the claims of an id_token received from the token endpoint.
func testIDToken(gen int) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]interface{}{
		"iss": "https://idp.example.com",
		"sub": "user-1",
		"sid": "idp-session-1",
		"aud": []string{"orders-web"},
		"gen": gen,
	})
	return enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// harness drives oauth2-session (pol) on its own routes and oauth2-session-proxy (proxy) on every
// other operation, both built from the same params as an API would configure them.
type harness struct {
	t     *testing.T
	pol   *Policy
	proxy *ProxyPolicy
	mr    *miniredis.Miniredis
	idp   *fakeIdP
	clock time.Time
}

func newHarness(t *testing.T, overrides map[string]interface{}) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	idp := newFakeIdP(t)
	params := validParams()
	params["tokenEndpoint"] = idp.srv.URL + "/token"
	params["postLoginRedirect"] = "/orders/v1/"
	params["postLogoutRedirect"] = "/orders/v1/bye"
	params["scopes"] = []interface{}{"openid", "orders:read"}
	host, port, _ := strings.Cut(mr.Addr(), ":")
	portNum, _ := strconv.Atoi(port)
	params["redis"] = map[string]interface{}{"host": host, "port": portNum}
	for k, v := range overrides {
		params[k] = v
	}
	pp, err := GetPolicy(policy.PolicyMetadata{RouteName: "test"}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	px, err := NewProxyPolicy(policy.PolicyMetadata{RouteName: "test-proxy"}, params)
	if err != nil {
		t.Fatalf("NewProxyPolicy: %v", err)
	}
	h := &harness{t: t, pol: pp.(*Policy), proxy: px, mr: mr, idp: idp, clock: time.Unix(1_800_000_000, 0)}
	for _, p := range []*Policy{h.pol, h.proxy.Policy} {
		p.now = func() time.Time { return h.clock }
		p.tokens.now = func() time.Time { return h.clock }
	}
	return h
}

func (h *harness) request(op, method, path, cookie string) *policy.RequestHeaderContext {
	headers := map[string][]string{}
	if cookie != "" {
		headers["cookie"] = []string{cookie}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{OperationPath: op, Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(headers),
		Path:          path,
		Method:        method,
	}
}

func (h *harness) call(op, method, path, cookie string) (policy.RequestHeaderAction, *policy.RequestHeaderContext) {
	rc := h.request(op, method, path, cookie)
	c := h.pol.cfg
	switch op {
	case c.loginPath, c.callbackPath, c.logoutPath, c.checkSessionPath, c.userinfoPath, c.refreshPath:
		return h.pol.OnRequestHeaders(context.Background(), rc, nil), rc
	}
	return h.proxy.OnRequestHeaders(context.Background(), rc, nil), rc
}

func immediate(t *testing.T, a policy.RequestHeaderAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", a)
	}
	return resp
}

// cookiePair returns "name=value" from a Set-Cookie header value.
func cookiePair(setCookie string) string {
	pair, _, _ := strings.Cut(setCookie, ";")
	return pair
}

// login runs /login then /callback and returns the session cookie pair ("X-ABC=...").
func (h *harness) login() string {
	h.t.Helper()
	resp := immediate(h.t, first(h.call("/login", "GET", "/orders/v1/login?returnTo=/orders/v1/orders/42", "")))
	loc, _ := url.Parse(resp.Headers["location"])
	state := loc.Query().Get("state")
	stateCookie := cookiePair(resp.Headers["set-cookie"])

	resp = immediate(h.t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, stateCookie)))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("callback status = %d, body %s", resp.StatusCode, resp.Body)
	}
	return cookiePair(resp.Headers["set-cookie"])
}

func first(a policy.RequestHeaderAction, _ *policy.RequestHeaderContext) policy.RequestHeaderAction {
	return a
}

func assertUnauthorized(t *testing.T, a policy.RequestHeaderAction) {
	t.Helper()
	resp := immediate(t, a)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if string(resp.Body) != `{"error":"unauthorized","message":"Invalid or expired credentials."}` {
		t.Fatalf("unexpected 401 body %s", resp.Body)
	}
}

func TestLogin_WithoutSession_RedirectsToAuthorizationEndpoint(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"authorizationRequestParams": map[string]interface{}{"prompt": "login"}})
	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login?returnTo=/orders/v1/orders/42", "")))

	if resp.StatusCode != http.StatusFound || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("status = %d, headers %v", resp.StatusCode, resp.Headers)
	}
	loc, err := url.Parse(resp.Headers["location"])
	if err != nil || loc.Host != "idp.example.com" || loc.Path != "/oauth2/authorize" {
		t.Fatalf("location = %q", resp.Headers["location"])
	}
	q := loc.Query()
	want := map[string]string{
		"response_type": "code",
		"client_id":     "orders-web",
		"redirect_uri":  "https://gw.example.com/orders/v1/callback",
		"scope":         "openid orders:read",
		"prompt":        "login",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Has("code_challenge") || q.Has("nonce") {
		t.Error("PKCE and nonce must not be sent")
	}
	state := q.Get("state")
	if len(state) != encodedIDLength {
		t.Fatalf("state = %q", state)
	}
	setCookie := resp.Headers["set-cookie"]
	if !strings.HasPrefix(setCookie, "X-ABC-state="+state+";") || !strings.Contains(setCookie, "SameSite=Lax") ||
		!strings.Contains(setCookie, "Max-Age=300") || !strings.Contains(setCookie, "HttpOnly") {
		t.Fatalf("state cookie = %q", setCookie)
	}
	stored, err := h.mr.Get(h.pol.store.stateKey(state))
	if err != nil || stored != "/orders/v1/orders/42" {
		t.Fatalf("stored returnTo = %q, %v", stored, err)
	}
	if h.mr.Exists("oauth2-session:v1:state:" + state) {
		t.Fatal("the raw state must not be used as a Redis key")
	}
}

func TestLogin_UnsafeReturnToFallsBackToPostLoginRedirect(t *testing.T) {
	h := newHarness(t, nil)
	for _, rt := range []string{"//evil.com", "https://evil.com", "/\\evil.com"} {
		resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login?returnTo="+url.QueryEscape(rt), "")))
		loc, _ := url.Parse(resp.Headers["location"])
		stored, _ := h.mr.Get(h.pol.store.stateKey(loc.Query().Get("state")))
		if stored != "/orders/v1/" {
			t.Errorf("returnTo %q stored as %q", rt, stored)
		}
	}
}

func TestCallback_CreatesEncryptedSessionAndRedirects(t *testing.T) {
	h := newHarness(t, nil)
	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login?returnTo=/orders/v1/orders/42", "")))
	loc, _ := url.Parse(resp.Headers["location"])
	state := loc.Query().Get("state")
	stateCookie := cookiePair(resp.Headers["set-cookie"])

	resp = immediate(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, stateCookie)))
	if resp.StatusCode != http.StatusFound || resp.Headers["location"] != "/orders/v1/orders/42" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Headers["location"])
	}
	setCookie := resp.Headers["set-cookie"]
	want := "; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax"
	if !strings.HasPrefix(setCookie, "X-ABC=") || !strings.HasSuffix(setCookie, want) {
		t.Fatalf("session cookie = %q", setCookie)
	}
	sid, ok := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookiePair(setCookie), "X-ABC="))
	if !ok {
		t.Fatal("issued cookie does not verify")
	}

	if h.mr.Exists(h.pol.store.stateKey(state)) {
		t.Fatal("state must be deleted after use")
	}
	key := h.pol.store.sessionKey(sid)
	raw, err := h.mr.Get(key)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if strings.Contains(raw, "at-1") || strings.Contains(raw, "rt-1") {
		t.Fatal("tokens must be encrypted at rest")
	}
	if ttl := h.mr.TTL(key); ttl != 30*time.Minute {
		t.Fatalf("session TTL = %v, want idle timeout", ttl)
	}
}

func TestCallback_Rejections(t *testing.T) {
	h := newHarness(t, nil)
	start := func() (string, string) {
		resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login", "")))
		loc, _ := url.Parse(resp.Headers["location"])
		return loc.Query().Get("state"), cookiePair(resp.Headers["set-cookie"])
	}

	state, cookie := start()
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, "")))
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state=other", cookie)))

	state, cookie = start()
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?error=access_denied&state="+state, cookie)))

	state, cookie = start()
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=bad-code&state="+state, cookie)))

	// A state value works once, even with the matching cookie.
	state, cookie = start()
	if resp := immediate(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, cookie))); resp.StatusCode != http.StatusFound {
		t.Fatalf("first callback status = %d", resp.StatusCode)
	}
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, cookie)))

	// An expired state is gone from Redis.
	state, cookie = start()
	h.mr.FastForward(6 * time.Minute)
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+state, cookie)))
}

func TestCallback_ReplacesPreviousSession(t *testing.T) {
	h := newHarness(t, nil)
	oldCookie := h.login()
	oldSID, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(oldCookie, "X-ABC="))

	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login", "")))
	loc, _ := url.Parse(resp.Headers["location"])
	cookies := cookiePair(resp.Headers["set-cookie"]) + "; " + oldCookie
	resp = immediate(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+loc.Query().Get("state"), cookies)))

	newSID, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookiePair(resp.Headers["set-cookie"]), "X-ABC="))
	if newSID == oldSID {
		t.Fatal("a new session id must be issued on every login")
	}
	if h.mr.Exists(h.pol.store.sessionKey(oldSID)) {
		t.Fatal("the previous session must be removed")
	}
}

func TestProtected_AddsBearerAndStripsSessionCookies(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()

	action, rc := h.call("/orders", "GET", "/orders/v1/orders", "theme=dark; "+cookie+"; X-ABC-state=leftover")
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected upstream modifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer at-1" {
		t.Fatalf("authorization = %q", mods.HeadersToSet["Authorization"])
	}
	if mods.HeadersToSet["cookie"] != "theme=dark" {
		t.Fatalf("forwarded cookie = %q", mods.HeadersToSet["cookie"])
	}
	ac := rc.AuthContext
	if ac == nil || !ac.Authenticated || ac.AuthType != AuthType || !ac.Scopes["orders:read"] {
		t.Fatalf("auth context = %+v", ac)
	}
	if _, set := rc.Metadata[metadataKeySetCookie]; set {
		t.Fatal("no cookie should be re-issued without a refresh")
	}

	// Only the session cookie: the Cookie header is removed entirely.
	action, _ = h.call("/orders", "GET", "/orders/v1/orders", cookie)
	if mods := action.(policy.UpstreamRequestHeaderModifications); len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "cookie" {
		t.Fatalf("cookie header should be removed, got %+v", mods)
	}
}

func TestProtected_WithoutValidSession(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))

	action, rc := h.call("/orders", "GET", "/orders/v1/orders", "")
	assertUnauthorized(t, action)
	if rc.AuthContext == nil || rc.AuthContext.Authenticated {
		t.Fatal("auth context must record the failure")
	}

	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie+"x")))
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie+"; "+cookie)))

	// Unknown session id with a valid signature.
	other, _ := newRandomID()
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", "X-ABC="+sessionCookieValue(h.pol.cfg.signingKey, other))))

	// Idle timeout: Redis expires the record.
	h.mr.FastForward(31 * time.Minute)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
	if h.mr.Exists(h.pol.store.sessionKey(sid)) {
		t.Fatal("idle session should be gone")
	}
}

func TestProtected_UseSlidesIdleTimeout(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	for i := 0; i < 3; i++ {
		h.mr.FastForward(20 * time.Minute)
		if _, ok := first(h.call("/orders", "GET", "/orders/v1/orders", cookie)).(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("request %d after 20m of idleness should still be authenticated", i)
		}
	}
}

func TestProtected_AbsoluteTimeoutEndsSession(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"absoluteSessionTimeout": "1h", "idleTimeout": "2h"})
	cookie := h.login()
	h.clock = h.clock.Add(time.Hour)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
}

func TestProtected_RefreshesNearExpiry(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))

	h.clock = h.clock.Add(56 * time.Minute) // access token expires at +60m, buffer 5m
	action, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	if mods.HeadersToSet["Authorization"] != "Bearer at-2" {
		t.Fatalf("authorization = %q", mods.HeadersToSet["Authorization"])
	}
	if h.idp.refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d", h.idp.refreshCalls.Load())
	}

	stored, err := h.pol.store.getSession(context.Background(), sid)
	if err != nil || stored.AccessToken != "at-2" || stored.RefreshToken != "rt-2" {
		t.Fatalf("stored session = %+v, %v", stored, err)
	}

	// The re-issued cookie keeps the same id and goes out on the backend's response.
	respCtx := &policy.ResponseHeaderContext{SharedContext: rc.SharedContext}
	out, ok := h.proxy.OnResponseHeaders(context.Background(), respCtx, nil).(policy.DownstreamResponseHeaderModifications)
	if !ok || len(out.HeadersToAppend["set-cookie"]) != 1 {
		t.Fatalf("response modifications = %+v", out)
	}
	if got := cookiePair(out.HeadersToAppend["set-cookie"][0]); got != cookie {
		t.Fatalf("re-issued cookie %q, want same value %q", got, cookie)
	}
	if !strings.Contains(out.HeadersToAppend["set-cookie"][0], "Max-Age=25440") {
		t.Fatalf("Max-Age should be the remaining absolute lifetime: %q", out.HeadersToAppend["set-cookie"][0])
	}
}

func TestProtected_RefreshRejectedEndsSession(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.idp.mu.Lock()
	h.idp.validRefresh = map[string]int{} // IdP revoked the refresh token
	h.idp.mu.Unlock()

	h.clock = h.clock.Add(56 * time.Minute)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
	h.clock = h.clock.Add(-50 * time.Minute)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
}

func TestProtected_TransientRefreshFailure(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"tokenRequestMaxRetries": 0})
	cookie := h.login()
	h.idp.refreshStatus.Store(http.StatusServiceUnavailable)

	// Token not yet expired: keep using it.
	h.clock = h.clock.Add(56 * time.Minute)
	mods := first(h.call("/orders", "GET", "/orders/v1/orders", cookie)).(policy.UpstreamRequestHeaderModifications)
	if mods.HeadersToSet["Authorization"] != "Bearer at-1" {
		t.Fatalf("authorization = %q", mods.HeadersToSet["Authorization"])
	}

	// Token expired: the service is unavailable, but the session survives for a later retry.
	h.clock = h.clock.Add(10 * time.Minute)
	if resp := immediate(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	h.idp.refreshStatus.Store(0)
	mods = first(h.call("/orders", "GET", "/orders/v1/orders", cookie)).(policy.UpstreamRequestHeaderModifications)
	if mods.HeadersToSet["Authorization"] != "Bearer at-2" {
		t.Fatalf("after recovery authorization = %q", mods.HeadersToSet["Authorization"])
	}
}

func TestProtected_ConcurrentRefreshCallsIdPOnce(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.idp.refreshDelay = 200 * time.Millisecond
	h.clock = h.clock.Add(61 * time.Minute) // expired: every request needs the new token

	const n = 5
	var wg sync.WaitGroup
	results := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if mods, ok := first(h.call("/orders", "GET", "/orders/v1/orders", cookie)).(policy.UpstreamRequestHeaderModifications); ok {
				results[i] = mods.HeadersToSet["Authorization"]
			}
		}(i)
	}
	wg.Wait()

	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
	for i, r := range results {
		if r != "Bearer at-2" {
			t.Errorf("request %d got %q", i, r)
		}
	}
}

func TestLogin_WithValidSession_ReturnsToTarget(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login?returnTo=/orders/v1/orders/7", cookie)))
	if resp.StatusCode != http.StatusFound || resp.Headers["location"] != "/orders/v1/orders/7" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Headers["location"])
	}
	if cookiePair(resp.Headers["set-cookie"]) != cookie {
		t.Fatalf("cookie should be re-issued with the same value, got %q", resp.Headers["set-cookie"])
	}
}

func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()

	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusFound || resp.Headers["location"] != "/orders/v1/bye" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Headers["location"])
	}
	if !strings.HasPrefix(resp.Headers["set-cookie"], "X-ABC=; Path=/; Max-Age=0;") {
		t.Fatalf("set-cookie = %q", resp.Headers["set-cookie"])
	}
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
}

func TestLogout_RedirectsToEndSessionEndpoint(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"endSessionEndpoint": "https://idp.example.com/oidc/logout"})
	cookie := h.login()

	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	loc, _ := url.Parse(resp.Headers["location"])
	q := loc.Query()
	if loc.Host != "idp.example.com" || q.Get("id_token_hint") != testIDToken(1) ||
		q.Get("post_logout_redirect_uri") != "https://gw.example.com/orders/v1/bye" || q.Get("client_id") != "orders-web" {
		t.Fatalf("location = %q", resp.Headers["location"])
	}
}

func TestAuthRoutes_OnlyAcceptGET(t *testing.T) {
	h := newHarness(t, nil)
	for _, op := range []string{"/login", "/callback", "/checksession", "/userinfo"} {
		resp := immediate(t, first(h.call(op, "POST", "/orders/v1"+op, "")))
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Headers["allow"] != "GET" {
			t.Errorf("%s: status %d", op, resp.StatusCode)
		}
	}
	resp := immediate(t, first(h.call("/logout", "PUT", "/orders/v1/logout", "")))
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Headers["allow"] != "GET, POST" {
		t.Errorf("PUT /logout: status %d allow %q", resp.StatusCode, resp.Headers["allow"])
	}
}

func TestRedisUnavailable_FailsClosed(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"redis": map[string]interface{}{"host": "127.0.0.1", "port": 1}})
	h.mr.Close()
	cookie := "X-ABC=" + sessionCookieValue(h.pol.cfg.signingKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	for _, op := range []string{"/orders", "/login"} {
		resp := immediate(t, first(h.call(op, "GET", "/orders/v1"+op, cookie)))
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d, want 503", op, resp.StatusCode)
		}
	}
	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(resp.Headers["set-cookie"], "Max-Age=0") {
		t.Fatalf("logout must report the failure and still clear the cookie: %d %v", resp.StatusCode, resp.Headers)
	}
}

func TestCallback_WritesBackchannelIndex(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"issuer": "https://idp.example.com"})
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))

	for _, key := range []string{
		h.pol.store.idpIndexKey("sid", "https://idp.example.com", "idp-session-1"),
		h.pol.store.idpIndexKey("sub", "https://idp.example.com", "user-1"),
	} {
		members, err := h.mr.SMembers(key)
		if err != nil || len(members) != 1 || members[0] != hashID(sid) {
			t.Fatalf("index %s = %v, %v", key, members, err)
		}
		if ttl := h.mr.TTL(key); ttl != 8*time.Hour {
			t.Fatalf("index TTL = %v, want the absolute session timeout", ttl)
		}
		if strings.Contains(key, "idp-session-1") || strings.Contains(key, "user-1") {
			t.Fatalf("index key must not contain the raw identifier: %s", key)
		}
	}
}

func TestCallback_NoIndexWithoutIssuer(t *testing.T) {
	h := newHarness(t, nil)
	h.login()
	if h.mr.Exists(h.pol.store.idpIndexKey("sub", "https://idp.example.com", "user-1")) {
		t.Fatal("no index should be written when issuer is not configured")
	}
}

func TestCallback_RejectsIDTokenFromAnotherIssuer(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"issuer": "https://other-idp.example.com"})
	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login", "")))
	loc, _ := url.Parse(resp.Headers["location"])
	stateCookie := cookiePair(resp.Headers["set-cookie"])
	assertUnauthorized(t, first(h.call("/callback", "GET", "/orders/v1/callback?code=good-code&state="+loc.Query().Get("state"), stateCookie)))
}

func TestRefresh_DoesNotRecreateSessionEndedMeanwhile(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	// A back-channel logout lands while the refresh call is in flight.
	h.idp.onRefresh = func() { h.mr.Del(h.pol.store.sessionKey(sid)) }

	h.clock = h.clock.Add(56 * time.Minute)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
	if h.mr.Exists(h.pol.store.sessionKey(sid)) {
		t.Fatal("the refresh must not recreate a session that was ended")
	}
}

func TestParseIDTokenClaims(t *testing.T) {
	c, err := parseIDTokenClaims(testIDToken(1))
	if err != nil || c.Iss != "https://idp.example.com" || c.Sub != "user-1" || c.Sid != "idp-session-1" || !c.hasAudience("orders-web") {
		t.Fatalf("claims = %+v, %v", c, err)
	}
	if c.hasAudience("someone-else") {
		t.Fatal("unexpected audience match")
	}
	single := &idTokenClaims{Aud: json.RawMessage(`"orders-web"`)}
	if !single.hasAudience("orders-web") {
		t.Fatal("a string aud must match")
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"} {
		if _, err := parseIDTokenClaims(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

// backendResponse runs OnResponseHeaders for a request whose backend answered status.
func (h *harness) backendResponse(rc *policy.RequestHeaderContext, status int) policy.ResponseHeaderAction {
	respCtx := &policy.ResponseHeaderContext{
		SharedContext:  rc.SharedContext,
		ResponseStatus: status,
		Upstream:       &policy.UpstreamResponseContext{Response: &policy.UpstreamResponse{StatusCode: status}},
	}
	return h.proxy.OnResponseHeaders(context.Background(), respCtx, nil)
}

func bearerOf(t *testing.T, a policy.RequestHeaderAction) string {
	t.Helper()
	mods, ok := a.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", a)
	}
	return mods.HeadersToSet["Authorization"]
}

func TestUpstream401_RefreshesOnNextRequest(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute) // token valid for another 50m

	action, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	if got := bearerOf(t, action); got != "Bearer at-1" {
		t.Fatalf("authorization = %q", got)
	}
	h.backendResponse(rc, http.StatusUnauthorized)

	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-2" {
		t.Fatalf("after backend 401 authorization = %q, want the refreshed token", got)
	}
	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
}

func TestUpstream401_LoginRefreshesToo(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute)
	_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	h.backendResponse(rc, http.StatusUnauthorized)

	resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login", cookie)))
	if resp.StatusCode != http.StatusFound || resp.Headers["location"] != "/orders/v1/" {
		t.Fatalf("login = %d %q", resp.StatusCode, resp.Headers["location"])
	}
	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
}

func TestUpstream401_OtherStatusesIgnored(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute)
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
		h.backendResponse(rc, status)
	}
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-1" {
		t.Fatalf("authorization = %q", got)
	}
	if calls := h.idp.refreshCalls.Load(); calls != 0 {
		t.Fatalf("refresh calls = %d, want 0", calls)
	}
}

func TestUpstream401_CooldownProtectsNewToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()

	// Just logged in: a backend that rejects every token must not cause a refresh per request.
	h.clock = h.clock.Add(10 * time.Second)
	_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	h.backendResponse(rc, http.StatusUnauthorized)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-1" {
		t.Fatalf("authorization = %q", got)
	}

	// After the cooldown the 401 counts, and the refreshed token gets a new cooldown.
	h.clock = h.clock.Add(time.Minute)
	_, rc = h.call("/orders", "GET", "/orders/v1/orders", cookie)
	h.backendResponse(rc, http.StatusUnauthorized)
	action, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	if got := bearerOf(t, action); got != "Bearer at-2" {
		t.Fatalf("authorization = %q", got)
	}
	h.backendResponse(rc, http.StatusUnauthorized)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-2" {
		t.Fatalf("authorization = %q", got)
	}
	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
}

func TestUpstream401_DoesNotExpireAlreadyRefreshedToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute)
	_, stale := h.call("/orders", "GET", "/orders/v1/orders", cookie) // carries at-1

	_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	h.backendResponse(rc, http.StatusUnauthorized)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-2" {
		t.Fatalf("authorization = %q", got)
	}

	// A late 401 for at-1 must not expire at-2.
	h.backendResponse(stale, http.StatusUnauthorized)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-2" {
		t.Fatalf("authorization = %q", got)
	}
	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
}

func TestUpstream401_KeepsTTLAndEndsSessionWithoutRefreshToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	key := h.pol.store.sessionKey(sid)
	h.clock = h.clock.Add(10 * time.Minute)

	// Simulate an IdP that issued no refresh token.
	sess, _ := h.pol.store.getSession(context.Background(), sid)
	sess.RefreshToken = ""
	if _, err := h.pol.store.updateSession(context.Background(), sid, sess, 20*time.Minute); err != nil {
		t.Fatal(err)
	}

	_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie) // slides TTL to idleTimeout (30m)
	h.backendResponse(rc, http.StatusUnauthorized)
	if ttl := h.mr.TTL(key); ttl != 30*time.Minute {
		t.Fatalf("TTL after marking = %v, want it kept at 30m", ttl)
	}
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
	if h.mr.Exists(key) {
		t.Fatal("session should be deleted when the rejected token can't be refreshed")
	}
}

func TestUpstream401_Disabled(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"refreshOnUpstreamUnauthorized": false})
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute)
	_, rc := h.call("/orders", "GET", "/orders/v1/orders", cookie)
	if _, ok := rc.Metadata[metadataKeyUpstreamToken]; ok {
		t.Fatal("no token reference should be recorded when disabled")
	}
	h.backendResponse(rc, http.StatusUnauthorized)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-1" {
		t.Fatalf("authorization = %q", got)
	}
}

func jsonBody(t *testing.T, resp policy.ImmediateResponse) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		t.Fatalf("body %s: %v", resp.Body, err)
	}
	return m
}

func TestCheckSession_ActiveSession(t *testing.T) {
	h := newHarness(t, nil)
	loginAt := h.clock
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	key := h.pol.store.sessionKey(sid)
	h.mr.SetTTL(key, 5*time.Minute) // 25 idle minutes already used
	h.clock = h.clock.Add(25 * time.Minute)

	resp := immediate(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)))
	if resp.StatusCode != http.StatusOK || resp.Headers["cache-control"] != "no-store" || resp.Headers["content-type"] != "application/json" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Headers)
	}
	// Same payload as the session endpoint.
	sessionResp := immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)))
	if string(resp.Body) != string(sessionResp.Body) {
		t.Fatalf("checksession %s, session %s", resp.Body, sessionResp.Body)
	}
	body := jsonBody(t, resp)
	user, _ := body["user"].(map[string]interface{})
	if body["isSignedIn"] != true || user["sub"] != "user-1" || body["expiresAt"] != float64(loginAt.Add(time.Hour).Unix()) {
		t.Fatalf("body = %s", resp.Body)
	}
	if _, ok := resp.Headers["set-cookie"]; ok {
		t.Fatal("checksession must not set a cookie")
	}
}

func TestCheckSession_DoesNotSlideIdleTimeout(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	key := h.pol.store.sessionKey(sid)
	h.mr.SetTTL(key, 5*time.Minute)

	immediate(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)))
	if ttl := h.mr.TTL(key); ttl != 5*time.Minute {
		t.Fatalf("TTL = %v: checksession must not slide the idle timeout", ttl)
	}
}

func TestCheckSession_DoesNotRefresh(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(61 * time.Minute) // access token expired, refresh token still valid

	resp := immediate(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)))
	if body := jsonBody(t, resp); resp.StatusCode != http.StatusOK || body["isSignedIn"] != true {
		t.Fatalf("status %d body %s", resp.StatusCode, resp.Body)
	}
	if calls := h.idp.refreshCalls.Load(); calls != 0 {
		t.Fatalf("refresh calls = %d, want 0", calls)
	}
}

// assertSignedOut checks the ThunderID SDK payload for "no session". A request that carried a
// session cookie must get it expired; one without must get no Set-Cookie.
func assertSignedOut(t *testing.T, a policy.RequestHeaderAction, sentCookie bool) {
	t.Helper()
	resp := immediate(t, a)
	if resp.StatusCode != http.StatusOK || string(resp.Body) != `{"isSignedIn":false}` || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("status %d body %s", resp.StatusCode, resp.Body)
	}
	setCookie, ok := resp.Headers["set-cookie"]
	if sentCookie && !strings.HasPrefix(setCookie, "X-ABC=; Path=/; Max-Age=0;") {
		t.Fatalf("the session cookie should be expired, set-cookie = %q", setCookie)
	}
	if !sentCookie && ok {
		t.Fatalf("no Set-Cookie expected without a session cookie, got %q", setCookie)
	}
}

func TestCheckSession_NoSession(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))

	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", "")), false)
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie+"x")), true)

	// Expired access token and no refresh token: the session can't be used any more.
	sess, _ := h.pol.store.getSession(context.Background(), sid)
	sess.RefreshToken = ""
	if _, err := h.pol.store.updateSession(context.Background(), sid, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(61 * time.Minute)
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)

	// Past the absolute lifetime.
	h.clock = h.clock.Add(8 * time.Hour)
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)

	// After logout.
	h2 := newHarness(t, nil)
	c2 := h2.login()
	h2.call("/logout", "GET", "/orders/v1/logout", c2)
	assertSignedOut(t, first(h2.call("/checksession", "GET", "/orders/v1/checksession", c2)), true)
}

func TestCheckSession_RedisUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()
	resp := immediate(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestUserinfo_FromIDToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Minute)

	resp := immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)))
	if resp.StatusCode != http.StatusOK || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("status %d headers %v body %s", resp.StatusCode, resp.Headers, resp.Body)
	}
	body := jsonBody(t, resp)
	user, _ := body["user"].(map[string]interface{})
	if body["isSignedIn"] != true || user["sub"] != "user-1" || user["gen"] != float64(1) {
		t.Fatalf("body = %s", resp.Body)
	}
	// expiresAt is the access token's expiry: login + expires_in (3600s).
	if body["expiresAt"] != float64(h.clock.Add(-10*time.Minute).Add(time.Hour).Unix()) {
		t.Fatalf("expiresAt = %v", body["expiresAt"])
	}
	for _, k := range []string{"iss", "aud", "sid"} {
		if _, ok := user[k]; ok {
			t.Errorf("protocol claim %q must not be returned", k)
		}
	}
	if len(body) != 3 {
		t.Errorf("unexpected fields in %s", resp.Body)
	}
}

func TestUserinfo_RefreshUpdatesClaims(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(56 * time.Minute)

	resp := immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)))
	if resp.StatusCode != http.StatusOK || cookiePair(resp.Headers["set-cookie"]) != cookie {
		t.Fatalf("status %d set-cookie %q", resp.StatusCode, resp.Headers["set-cookie"])
	}
	body := jsonBody(t, resp)
	if user, _ := body["user"].(map[string]interface{}); user["gen"] != float64(2) {
		t.Fatalf("claims should come from the refreshed id_token: %s", resp.Body)
	}
	if body["expiresAt"] != float64(h.clock.Add(time.Hour).Unix()) {
		t.Fatalf("expiresAt should be the refreshed token's expiry: %v", body["expiresAt"])
	}
}

func TestUserinfo_WithoutIDToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	sess, _ := h.pol.store.getSession(context.Background(), sid)
	sess.IDToken = ""
	if _, err := h.pol.store.updateSession(context.Background(), sid, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	resp := immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)))
	body := jsonBody(t, resp)
	if user, ok := body["user"].(map[string]interface{}); resp.StatusCode != http.StatusOK || body["isSignedIn"] != true || !ok || len(user) != 0 {
		t.Fatalf("status %d body %s", resp.StatusCode, resp.Body)
	}
}

func TestUserinfo_NoSession(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.call("/logout", "GET", "/orders/v1/logout", cookie)

	// Every way of not having a session gets the same 200 {"isSignedIn":false}; a cookie that was
	// sent is expired.
	assertSignedOut(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", "")), false)
	assertSignedOut(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie+"x")), true)
	assertSignedOut(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)), true)
}

func TestCheckSession_DropsDeadSessionAndExpiresCookie(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	sess, _ := h.pol.store.getSession(context.Background(), sid)
	sess.RefreshToken = ""
	if _, err := h.pol.store.updateSession(context.Background(), sid, sess, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(61 * time.Minute) // access token expired, nothing to refresh it with

	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)
	if h.mr.Exists(h.pol.store.sessionKey(sid)) {
		t.Fatal("a session that can no longer be used should be deleted")
	}
}

func TestCheckSession_RedisDownKeepsCookie(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()
	resp := immediate(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)))
	if _, ok := resp.Headers["set-cookie"]; resp.StatusCode != http.StatusServiceUnavailable || ok {
		t.Fatalf("status %d, set-cookie present %v: a Redis outage must not sign the user out", resp.StatusCode, ok)
	}
}

func TestUserinfo_RedisUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()
	resp := immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie)))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (not a false isSignedIn)", resp.StatusCode)
	}
}

func TestSessionRoutes_CustomPathsAndGETOnly(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"checkSessionPath": "/me/session", "userinfoPath": "/me"})
	cookie := h.login()

	if resp := immediate(t, first(h.call("/me/session", "GET", "/orders/v1/me/session", cookie))); resp.StatusCode != http.StatusOK {
		t.Fatalf("checkSessionPath status = %d", resp.StatusCode)
	}
	if resp := immediate(t, first(h.call("/me", "GET", "/orders/v1/me", cookie))); resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfoPath status = %d", resp.StatusCode)
	}
	for _, op := range []string{"/me/session", "/me"} {
		resp := immediate(t, first(h.call(op, "POST", "/orders/v1"+op, cookie)))
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d", op, resp.StatusCode)
		}
	}
	// The default paths are now ordinary protected operations.
	if _, ok := first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatal("/checksession should be forwarded to the backend when checkSessionPath is changed")
	}
}

func TestLogout_RemovesSessionLockAndIndexEntries(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"issuer": "https://idp.example.com"})
	cookie := h.login()
	other := h.login() // a second browser of the same user
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	otherSID, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(other, "X-ABC="))
	lockKey := h.pol.store.lockKey(sid)
	if err := h.mr.Set(lockKey, "held"); err != nil {
		t.Fatal(err)
	}

	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if h.mr.Exists(h.pol.store.sessionKey(sid)) || h.mr.Exists(lockKey) {
		t.Fatal("session and refresh lock must be deleted")
	}
	for _, key := range []string{
		h.pol.store.idpIndexKey("sid", "https://idp.example.com", "idp-session-1"),
		h.pol.store.idpIndexKey("sub", "https://idp.example.com", "user-1"),
	} {
		members, _ := h.mr.SMembers(key)
		if len(members) != 1 || members[0] != hashID(otherSID) {
			t.Fatalf("index %s = %v, want only the other session", key, members)
		}
	}
	// The other browser is still logged in.
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", other))); got == "" {
		t.Fatal("other session should still work")
	}
}

func TestLogout_WithoutSessionOrTwice(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"endSessionEndpoint": "https://idp.example.com/oidc/logout"})
	cookie := h.login()

	firstResp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if !strings.Contains(firstResp.Headers["location"], "id_token_hint=") {
		t.Fatalf("first logout should carry id_token_hint: %q", firstResp.Headers["location"])
	}
	for name, c := range map[string]string{"again": cookie, "no cookie": "", "forged cookie": cookie + "x"} {
		resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", c)))
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Headers["set-cookie"], "X-ABC=; Path=/; Max-Age=0;") {
			t.Fatalf("%s: status %d set-cookie %q", name, resp.StatusCode, resp.Headers["set-cookie"])
		}
		loc, _ := url.Parse(resp.Headers["location"])
		if loc.Host != "idp.example.com" || loc.Query().Has("id_token_hint") {
			t.Fatalf("%s: location = %q", name, resp.Headers["location"])
		}
	}
}

func TestLogout_RedisUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()

	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Headers["set-cookie"], "X-ABC=; Path=/; Max-Age=0;") {
		t.Fatalf("cookie must be cleared even when Redis fails: %q", resp.Headers["set-cookie"])
	}
}

func TestLogout_UndecryptableRecordIsStillDeleted(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	key := h.pol.store.sessionKey(sid)
	if err := h.mr.Set(key, "garbage-from-an-old-encryption-key"); err != nil {
		t.Fatal(err)
	}

	resp := immediate(t, first(h.call("/logout", "GET", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusFound || h.mr.Exists(key) {
		t.Fatalf("status %d, record exists %v", resp.StatusCode, h.mr.Exists(key))
	}
}

// assertNoContent checks a successful ThunderID SDK refresh: 204, no body, not cacheable.
func assertNoContent(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if resp.StatusCode != http.StatusNoContent || len(resp.Body) != 0 || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("status %d body %q headers %v", resp.StatusCode, resp.Body, resp.Headers)
	}
}

func TestRefresh_ForcesRefreshWithRefreshToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()

	for round := 0; round < 2; round++ {
		h.clock = h.clock.Add(10 * time.Minute) // past the cooldown; token still valid
		resp := immediate(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie)))
		assertNoContent(t, resp)
		if cookiePair(resp.Headers["set-cookie"]) != cookie {
			t.Fatalf("round %d: set-cookie %q", round, resp.Headers["set-cookie"])
		}
	}
	if calls := h.idp.refreshCalls.Load(); calls != 2 {
		t.Fatalf("refresh calls = %d, want 2", calls)
	}
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-3" {
		t.Fatalf("authorization = %q", got)
	}
	// The SDK re-reads the session after a refresh: it shows the new token's expiry.
	body := jsonBody(t, immediate(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", cookie))))
	if body["expiresAt"] != float64(h.clock.Add(time.Hour).Unix()) {
		t.Fatalf("expiresAt = %v", body["expiresAt"])
	}
}

func TestRefresh_CooldownKeepsNewToken(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.clock = h.clock.Add(10 * time.Second)

	resp := immediate(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie)))
	assertNoContent(t, resp)
	if _, ok := resp.Headers["set-cookie"]; ok || h.idp.refreshCalls.Load() != 0 {
		t.Fatalf("no refresh expected within the cooldown (calls %d)", h.idp.refreshCalls.Load())
	}
}

func TestRefresh_RejectedRefreshTokenEndsSession(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.idp.mu.Lock()
	h.idp.validRefresh = map[string]int{}
	h.idp.mu.Unlock()
	h.clock = h.clock.Add(10 * time.Minute)

	assertUnauthorized(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie)))
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)
}

func TestRefresh_ConcurrentCallsRefreshOnce(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.idp.refreshDelay = 150 * time.Millisecond
	h.clock = h.clock.Add(10 * time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := immediate(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie))); resp.StatusCode != http.StatusNoContent {
				t.Errorf("status = %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if calls := h.idp.refreshCalls.Load(); calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}
}

func TestRefresh_NoSessionAndMethods(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	assertUnauthorized(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", "")))
	assertUnauthorized(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie+"x")))
	for _, method := range []string{"GET", "PUT"} {
		resp := immediate(t, first(h.call("/refresh", method, "/orders/v1/refresh", cookie)))
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Headers["allow"] != "POST" {
			t.Fatalf("%s: status %d allow %q", method, resp.StatusCode, resp.Headers["allow"])
		}
	}
	if calls := h.idp.refreshCalls.Load(); calls != 0 {
		t.Fatalf("refresh calls = %d, want 0", calls)
	}
}

func TestRefresh_RedisUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()
	if resp := immediate(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", cookie))); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func redirectURLOf(t *testing.T, resp policy.ImmediateResponse) *url.URL {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(resp.Body, &body); err != nil || len(body) != 1 || body["redirectUrl"] == "" {
		t.Fatalf("body %s: %v", resp.Body, err)
	}
	u, err := url.Parse(body["redirectUrl"])
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLogoutPOST_ReturnsRedirectURL(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"endSessionEndpoint": "https://idp.example.com/oidc/logout"})
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))

	resp := immediate(t, first(h.call("/logout", "POST", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusOK || resp.Headers["content-type"] != "application/json" || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Headers)
	}
	if _, ok := resp.Headers["location"]; ok {
		t.Fatal("POST logout must not redirect")
	}
	if !strings.HasPrefix(resp.Headers["set-cookie"], "X-ABC=; Path=/; Max-Age=0;") {
		t.Fatalf("set-cookie = %q", resp.Headers["set-cookie"])
	}
	u := redirectURLOf(t, resp)
	q := u.Query()
	if u.Host != "idp.example.com" || q.Get("id_token_hint") != testIDToken(1) ||
		q.Get("post_logout_redirect_uri") != "https://gw.example.com/orders/v1/bye" || q.Get("client_id") != "orders-web" {
		t.Fatalf("redirectUrl = %s", u)
	}
	if h.mr.Exists(h.pol.store.sessionKey(sid)) {
		t.Fatal("session must be deleted")
	}
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)

	// Again, without a session: same destination, no id_token_hint.
	u = redirectURLOf(t, immediate(t, first(h.call("/logout", "POST", "/orders/v1/logout", cookie))))
	if u.Host != "idp.example.com" || u.Query().Has("id_token_hint") {
		t.Fatalf("second redirectUrl = %s", u)
	}
}

func TestLogoutPOST_WithoutEndSessionEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	resp := immediate(t, first(h.call("/logout", "POST", "/orders/v1/logout", cookie)))
	if string(resp.Body) != `{"redirectUrl":"/orders/v1/bye"}` {
		t.Fatalf("body = %s", resp.Body)
	}
}

func TestLogoutPOST_RedisUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	h.mr.Close()
	resp := immediate(t, first(h.call("/logout", "POST", "/orders/v1/logout", cookie)))
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.HasPrefix(resp.Headers["set-cookie"], "X-ABC=; Path=/; Max-Age=0;") {
		t.Fatalf("status %d set-cookie %q", resp.StatusCode, resp.Headers["set-cookie"])
	}
}

func TestContinueWithoutCookie_PassesRequestsWithoutCookie(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"continueWithoutCookie": true})

	for name, cookieHeader := range map[string]string{"no cookie header": "", "only other cookies": "theme=dark; X-ABC-state=abc"} {
		rc := h.request("/orders", "GET", "/orders/v1/orders", cookieHeader)
		previous := &policy.AuthContext{Authenticated: true, AuthType: "jwt"}
		rc.SharedContext.AuthContext = previous
		rc.Headers = policy.NewHeaders(map[string][]string{
			"cookie":        {cookieHeader},
			"authorization": {"Bearer client-token"},
		})
		action := h.proxy.OnRequestHeaders(context.Background(), rc, nil)
		mods, ok := action.(policy.UpstreamRequestHeaderModifications)
		if !ok || len(mods.HeadersToSet) != 0 || len(mods.HeadersToRemove) != 0 {
			t.Fatalf("%s: expected an unchanged request, got %#v", name, action)
		}
		if rc.SharedContext.AuthContext != previous {
			t.Fatalf("%s: the AuthContext must be left to the next policies", name)
		}
		if _, ok := rc.Metadata[metadataKeyUpstreamToken]; ok {
			t.Fatalf("%s: no token reference expected", name)
		}
		// A backend 401 for such a request touches no session.
		h.backendResponse(rc, http.StatusUnauthorized)
	}
	if h.idp.refreshCalls.Load() != 0 {
		t.Fatal("no refresh expected")
	}
}

func TestContinueWithoutCookie_CookieStillAuthenticated(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"continueWithoutCookie": true})
	cookie := h.login()

	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-1" {
		t.Fatalf("authorization = %q", got)
	}
	// A cookie that is present but not valid is rejected, not passed on.
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie+"x")))
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie+"; "+cookie)))
	h.call("/logout", "GET", "/orders/v1/logout", cookie)
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
}

func TestContinueWithoutCookie_AuthRoutesUnchanged(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"continueWithoutCookie": true})
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", "")), false)
	assertSignedOut(t, first(h.call("/userinfo", "GET", "/orders/v1/userinfo", "")), false)
	assertUnauthorized(t, first(h.call("/refresh", "POST", "/orders/v1/refresh", "")))
	if resp := immediate(t, first(h.call("/login", "GET", "/orders/v1/login", ""))); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
}

func TestContinueWithoutCookie_DefaultRejects(t *testing.T) {
	h := newHarness(t, nil)
	if h.proxy.cfg.continueWithoutCookie {
		t.Fatal("continueWithoutCookie must default to false")
	}
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", "")))
}

func TestSession_OtherOperationsAreNotServed(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	resp := immediate(t, h.pol.OnRequestHeaders(context.Background(), h.request("/orders", "GET", "/orders/v1/orders", cookie), nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if h.pol.Mode().ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatal("oauth2-session must not process responses")
	}
}

func TestProxy_AnyOperationPathIsProtected(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	// The proxy authenticates whatever it is attached to, including paths that oauth2-session
	// serves: a wildcard proxy route never turns into a login route.
	for _, op := range []string{"/*", "/login", "/logout", "/refresh"} {
		rc := h.request(op, "GET", "/orders/v1/anything", cookie)
		if got := bearerOf(t, h.proxy.OnRequestHeaders(context.Background(), rc, nil)); got != "Bearer at-1" {
			t.Fatalf("%s: authorization = %q", op, got)
		}
		assertUnauthorized(t, h.proxy.OnRequestHeaders(context.Background(), h.request(op, "GET", "/orders/v1/anything", ""), nil))
	}
	if m := h.proxy.Mode(); m.ResponseHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("unexpected mode %+v", m)
	}
}

func TestProxy_SessionFromAnotherKeyIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	params := validParams()
	params["tokenEndpoint"] = h.idp.srv.URL + "/token"
	params["sessionSigningKey"] = strings.Repeat("x", 32)
	host, port, _ := strings.Cut(h.mr.Addr(), ":")
	portNum, _ := strconv.Atoi(port)
	params["redis"] = map[string]interface{}{"host": host, "port": portNum}
	px, err := NewProxyPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	assertUnauthorized(t, px.OnRequestHeaders(context.Background(), h.request("/orders", "GET", "/orders/v1/orders", cookie), nil))
}

// storedSession decrypts the Redis record behind a session cookie pair.
func (h *harness) storedSession(cookie string) *session {
	h.t.Helper()
	sid, ok := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	if !ok {
		h.t.Fatal("cookie does not verify")
	}
	sess, err := h.pol.store.getSession(context.Background(), sid)
	if err != nil || sess == nil {
		h.t.Fatalf("session not found: %v", err)
	}
	return sess
}

func TestDeviceSecret_StoredAtLoginAndKeptAcrossRefresh(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	if got := h.storedSession(cookie).DeviceSecret; got != "ds-1" {
		t.Fatalf("device_secret after login = %q", got)
	}
	// The record member is named as oauth2-native-sso reads it.
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	raw, _ := h.mr.Get(h.pol.store.sessionKey(sid))
	plain, err := h.pol.store.decryptSession(h.pol.store.sessionKey(sid), []byte(raw))
	if err != nil || plain.DeviceSecret != "ds-1" {
		t.Fatalf("decrypt: %v", err)
	}
	if b, _ := json.Marshal(plain); !strings.Contains(string(b), `"device_secret":"ds-1"`) {
		t.Fatalf("record JSON %s", b)
	}

	// A refresh without a device_secret keeps the stored one.
	h.clock = h.clock.Add(58 * time.Minute)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-2" {
		t.Fatalf("authorization = %q", got)
	}
	if got := h.storedSession(cookie).DeviceSecret; got != "ds-1" {
		t.Fatalf("device_secret after refresh = %q", got)
	}

	// A rotated device_secret replaces it.
	h.idp.rotateDevice.Store(true)
	h.clock = h.clock.Add(58 * time.Minute)
	if got := bearerOf(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie))); got != "Bearer at-3" {
		t.Fatalf("authorization = %q", got)
	}
	if got := h.storedSession(cookie).DeviceSecret; got != "ds-3" {
		t.Fatalf("device_secret after rotation = %q", got)
	}
}

func TestDeviceSecret_NeverReturnedToTheBrowser(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	for _, op := range []string{"/userinfo", "/checksession"} {
		resp := immediate(t, first(h.call(op, "GET", "/orders/v1"+op, cookie)))
		if strings.Contains(string(resp.Body), "ds-1") {
			t.Fatalf("%s leaks the device_secret: %s", op, resp.Body)
		}
	}
	rc := h.request("/orders", "GET", "/orders/v1/orders", cookie)
	mods := h.proxy.OnRequestHeaders(context.Background(), rc, nil).(policy.UpstreamRequestHeaderModifications)
	for k, v := range mods.HeadersToSet {
		if strings.Contains(v, "ds-1") {
			t.Fatalf("header %s carries the device_secret", k)
		}
	}
}

func TestUndecryptableSession_IsDiscardedNotUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.login()
	sid, _ := verifySessionCookie(h.pol.cfg.signingKey, strings.TrimPrefix(cookie, "X-ABC="))
	key := h.pol.store.sessionKey(sid)

	// The same record under another tokenEncryptionKey, as after rotating it.
	p := validParams()
	p["tokenEncryptionKey"] = strings.Repeat("r", 32)
	c, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	other, err := newSessionStore(nil, c.redis, c.encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := other.sealSession(key, &session{AccessToken: "at-old", ExpiresAt: h.clock.Add(time.Hour).Unix(), CreatedAt: h.clock.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.mr.Set(key, string(sealed)); err != nil {
		t.Fatal(err)
	}

	// Signed out, cookie expired, record gone - not 503.
	assertSignedOut(t, first(h.call("/checksession", "GET", "/orders/v1/checksession", cookie)), true)
	if h.mr.Exists(key) {
		t.Fatal("the undecryptable record must be deleted")
	}

	if err := h.mr.Set(key, string(sealed)); err != nil {
		t.Fatal(err)
	}
	assertUnauthorized(t, first(h.call("/orders", "GET", "/orders/v1/orders", cookie)))
	if h.mr.Exists(key) {
		t.Fatal("the undecryptable record must be deleted")
	}
}
