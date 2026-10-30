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
		idp.issue(w, 1)
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
		idp.issue(w, gen+1)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (idp *fakeIdP) issue(w http.ResponseWriter, gen int) {
	rt := "rt-" + strconv.Itoa(gen)
	idp.mu.Lock()
	idp.validRefresh[rt] = gen
	idp.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  "at-" + strconv.Itoa(gen),
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid orders:read",
		"id_token":      testIDToken(gen),
	})
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

type harness struct {
	t     *testing.T
	pol   *Policy
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
	h := &harness{t: t, pol: pp.(*Policy), mr: mr, idp: idp, clock: time.Unix(1_800_000_000, 0)}
	h.pol.now = func() time.Time { return h.clock }
	h.pol.tokens.now = func() time.Time { return h.clock }
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
	return h.pol.OnRequestHeaders(context.Background(), rc, nil), rc
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
	out, ok := h.pol.OnResponseHeaders(context.Background(), respCtx, nil).(policy.DownstreamResponseHeaderModifications)
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
	for _, op := range []string{"/login", "/callback", "/logout"} {
		resp := immediate(t, first(h.call(op, "POST", "/orders/v1"+op, "")))
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Headers["allow"] != "GET" {
			t.Errorf("%s: status %d", op, resp.StatusCode)
		}
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
