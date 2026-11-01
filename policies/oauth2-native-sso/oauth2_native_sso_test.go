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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
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

const (
	testIssuer       = "https://idp.example.com"
	testPrefix       = "oauth2-session:v1:"
	sourceCookie     = "__Host-orders"
	targetCookie     = "__Host-billing"
	sourceSigning    = "source-signing-secret-0123456789abcdef"
	sourceEncryption = "source-encryption-secret-0123456789abcd"
	targetSigning    = "target-signing-secret-0123456789abcdef"
	targetEncryption = "target-encryption-secret-0123456789abcd"
)

// The helpers below re-implement oauth2-session's cookie and record format independently of the
// package code, so the tests prove compatibility with it rather than with themselves.

func deriveKey(secret, info string) []byte {
	k, err := hkdf.Key(sha3.New256, []byte(secret), nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func sessKey(sid string) string {
	sum := sha3.Sum256([]byte(sid))
	return testPrefix + "sess:" + hex.EncodeToString(sum[:])
}

func gcm(secret string) cipher.AEAD {
	block, _ := aes.NewCipher(deriveKey(secret, "oauth2-session token encryption v1"))
	aead, _ := cipher.NewGCM(block)
	return aead
}

func sealRecord(secret, key string, record map[string]interface{}) []byte {
	plain, _ := json.Marshal(record)
	aead := gcm(secret)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, []byte(key))
}

func openRecord(t *testing.T, secret, key string, raw []byte) map[string]interface{} {
	t.Helper()
	aead := gcm(secret)
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(key))
	if err != nil {
		t.Fatalf("record under %s does not decrypt with oauth2-session's scheme: %v", key, err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(plain, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func cookieFor(secret, sid string) string {
	mac := hmac.New(func() hash.Hash { return sha3.New256() }, deriveKey(secret, "oauth2-session cookie signing v1"))
	mac.Write([]byte(sid))
	return sid + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func randomSID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func idToken(aud, sid string) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]interface{}{"iss": testIssuer, "sub": "user-1", "sid": sid, "aud": aud})
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

// fakeIdP is a token endpoint implementing the Native SSO token exchange for client billing-web.
type fakeIdP struct {
	srv        *httptest.Server
	calls      atomic.Int32
	status     atomic.Int32 // non-zero forces this error status
	delay      time.Duration
	idTokenSid string
	rotateTo   string
	omitScope  bool // the response has no scope member
	mu         sync.Mutex
	lastForm   url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	idp := &fakeIdP{idTokenSid: "idp-session-1", rotateTo: "ds-2"}
	idp.srv = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	idp.calls.Add(1)
	time.Sleep(idp.delay)
	_ = r.ParseForm()
	idp.mu.Lock()
	idp.lastForm = r.PostForm
	idp.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if s := idp.status.Load(); s != 0 {
		w.WriteHeader(int(s))
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"device_secret revoked"}`))
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != "billing-web" || pass != "billing-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	resp := map[string]interface{}{
		"access_token":      "billing-at",
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"refresh_token":     "billing-rt",
		"id_token":          idToken("billing-web", idp.idTokenSid),
		"scope":             "openid billing:read",
		"expires_in":        "600",
	}
	if idp.rotateTo != "" {
		resp["device_secret"] = idp.rotateTo
	}
	if idp.omitScope {
		delete(resp, "scope")
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type harness struct {
	t     *testing.T
	pol   *Policy
	mr    *miniredis.Miniredis
	idp   *fakeIdP
	clock time.Time
}

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
		"clientId":      "billing-web",
		"clientSecret":  "billing-secret",
		"issuer":        testIssuer,
		"source": map[string]interface{}{
			"cookieName":         sourceCookie,
			"sessionSigningKey":  sourceSigning,
			"tokenEncryptionKey": sourceEncryption,
		},
		"target": map[string]interface{}{
			"cookieName":         targetCookie,
			"sessionSigningKey":  targetSigning,
			"tokenEncryptionKey": targetEncryption,
		},
	}
}

func newHarness(t *testing.T, overrides map[string]interface{}) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	idp := newFakeIdP(t)
	params := validParams()
	params["tokenEndpoint"] = idp.srv.URL + "/token"
	params["allowInsecureTokenEndpoint"] = true
	params["scopes"] = []interface{}{"openid", "billing:read"}
	params["postLoginRedirect"] = "/billing/v1/"
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
	h := &harness{t: t, pol: pp.(*Policy), mr: mr, idp: idp, clock: time.Now().Truncate(time.Second)}
	h.pol.now = func() time.Time { return h.clock }
	h.pol.tokens.now = func() time.Time { return h.clock }
	return h
}

// seedSource stores an oauth2-session record for API A and returns its cookie pair.
func (h *harness) seedSource(record map[string]interface{}) string {
	h.t.Helper()
	sid := randomSID()
	base := map[string]interface{}{
		"at":            "orders-at",
		"rt":            "orders-rt",
		"it":            idToken("orders-web", "idp-session-1"),
		"exp":           h.clock.Add(time.Hour).Unix(),
		"cat":           h.clock.Add(-time.Minute).Unix(),
		"device_secret": "ds-1",
		"zz":            "kept", // a member this policy doesn't know
	}
	for k, v := range record {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	key := sessKey(sid)
	if err := h.mr.Set(key, string(sealRecord(sourceEncryption, key, base))); err != nil {
		h.t.Fatal(err)
	}
	h.mr.SetTTL(key, 30*time.Minute)
	return sourceCookie + "=" + cookieFor(sourceSigning, sid) + "; other=1"
}

func (h *harness) call(op, method, path, cookie string) policy.RequestHeaderAction {
	headers := map[string][]string{}
	if cookie != "" {
		headers["cookie"] = []string{cookie}
	}
	rc := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{OperationPath: op, Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(headers),
		Path:          path,
		Method:        method,
	}
	return h.pol.OnRequestHeaders(context.Background(), rc, nil)
}

func immediate(t *testing.T, a policy.RequestHeaderAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T %+v", a, a)
	}
	return resp
}

func assertPass(t *testing.T, a policy.RequestHeaderAction) {
	t.Helper()
	mods, ok := a.(policy.UpstreamRequestHeaderModifications)
	if !ok || len(mods.HeadersToSet) != 0 || len(mods.HeadersToRemove) != 0 {
		t.Fatalf("expected the request to continue unchanged, got %T %+v", a, a)
	}
}

// targetSID returns the session ID in a target Set-Cookie, verifying its signature the
// oauth2-session way.
func targetSID(t *testing.T, setCookie string) string {
	t.Helper()
	pair, _, _ := strings.Cut(setCookie, ";")
	value, ok := strings.CutPrefix(pair, targetCookie+"=")
	if !ok {
		t.Fatalf("set-cookie %q is not the target cookie", setCookie)
	}
	sid, _, _ := strings.Cut(value, ".")
	if cookieFor(targetSigning, sid) != value {
		t.Fatalf("target cookie signature does not verify with oauth2-session's scheme")
	}
	return sid
}

func (h *harness) sessionKeys() []string {
	var out []string
	for _, k := range h.mr.Keys() {
		if strings.HasPrefix(k, testPrefix+"sess:") {
			out = append(out, k)
		}
	}
	return out
}

func TestLogin_SignsInWithNativeSSO(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.seedSource(map[string]interface{}{"cat": h.clock.Unix()})

	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login?returnTo=/billing/v1/invoices", cookie))
	if resp.StatusCode != http.StatusFound || resp.Headers["location"] != "/billing/v1/invoices" || resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("response = %d %v", resp.StatusCode, resp.Headers)
	}
	setCookie := resp.Headers["set-cookie"]
	for _, want := range []string{"Path=/", "Max-Age=28800", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(setCookie, want) {
			t.Errorf("set-cookie %q lacks %q", setCookie, want)
		}
	}

	// The token exchange request is the one Native SSO §4 defines.
	h.idp.mu.Lock()
	form := h.idp.lastForm
	h.idp.mu.Unlock()
	want := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      idToken("orders-web", "idp-session-1"),
		"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
		"actor_token":        "ds-1",
		"actor_token_type":   "urn:openid:params:token-type:device-secret",
		"audience":           testIssuer,
		"scope":              "openid billing:read",
		"client_id":          "billing-web",
	}
	if _, ok := form["resource"]; ok {
		t.Errorf("resource must not be sent unless configured")
	}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("form %s = %q, want %q", k, form.Get(k), v)
		}
	}
	if form.Has("client_secret") {
		t.Error("client_secret must not be sent in the form with client_secret_basic")
	}

	// The target record is an oauth2-session record under the target encryption key.
	sid := targetSID(t, setCookie)
	key := sessKey(sid)
	raw, err := h.mr.Get(key)
	if err != nil {
		t.Fatalf("target session not stored: %v", err)
	}
	rec := openRecord(t, targetEncryption, key, []byte(raw))
	if rec["at"] != "billing-at" || rec["rt"] != "billing-rt" || rec["tt"] != "Bearer" ||
		rec["it"] != idToken("billing-web", "idp-session-1") || rec["device_secret"] != "ds-2" ||
		fmt.Sprint(rec["sc"]) != "[openid billing:read]" {
		t.Fatalf("target record = %v", rec)
	}
	if int64(rec["exp"].(float64)) != h.clock.Add(600*time.Second).Unix() || int64(rec["cat"].(float64)) != h.clock.Unix() ||
		int64(rec["oat"].(float64)) != h.clock.Unix() {
		t.Fatalf("target record times = %v", rec)
	}
	if ttl := h.mr.TTL(key); ttl != 30*time.Minute {
		t.Fatalf("target session TTL = %v, want the idle timeout", ttl)
	}

	// The back-channel logout index lists it under the IdP's sid and sub.
	member := hashID(sid)
	for _, ik := range []string{
		testPrefix + "idp-sid:" + hashID(testIssuer+"\x00idp-session-1"),
		testPrefix + "idp-sub:" + hashID(testIssuer+"\x00user-1"),
	} {
		if ok, _ := h.mr.SIsMember(ik, member); !ok {
			t.Errorf("index %s does not list the target session", ik)
		}
	}

	// The rotated device_secret replaced the source's, every other member kept, TTL kept.
	srcSID, _, _ := strings.Cut(strings.TrimPrefix(cookie, sourceCookie+"="), ".")
	srcKey := sessKey(srcSID)
	srcRaw, _ := h.mr.Get(srcKey)
	src := openRecord(t, sourceEncryption, srcKey, []byte(srcRaw))
	if src["device_secret"] != "ds-2" || src["at"] != "orders-at" || src["zz"] != "kept" {
		t.Fatalf("source record after rotation = %v", src)
	}
	if ttl := h.mr.TTL(srcKey); ttl != 30*time.Minute {
		t.Fatalf("source TTL changed to %v", ttl)
	}
}

func TestLogin_NoRotation_KeepsSourceDeviceSecret(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.rotateTo = ""
	cookie := h.seedSource(nil)
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", cookie))
	if resp.Headers["location"] != "/billing/v1/" {
		t.Fatalf("location = %q, want postLoginRedirect", resp.Headers["location"])
	}
	sid := targetSID(t, resp.Headers["set-cookie"])
	raw, _ := h.mr.Get(sessKey(sid))
	if rec := openRecord(t, targetEncryption, sessKey(sid), []byte(raw)); rec["device_secret"] != "ds-1" {
		t.Fatalf("target device_secret = %v, want the source's", rec["device_secret"])
	}
}

// A response without scope granted the requested scopes (RFC 8693 §2.2.1), so the target session
// records those for oauth2-session's session endpoint.
func TestLogin_NoScopeInResponse_RecordsRequestedScopes(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"scopes": []interface{}{"openid", "billing:read", "billing:write"}})
	h.idp.omitScope = true
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", h.seedSource(nil)))
	sid := targetSID(t, resp.Headers["set-cookie"])
	raw, _ := h.mr.Get(sessKey(sid))
	rec := openRecord(t, targetEncryption, sessKey(sid), []byte(raw))
	if got := fmt.Sprint(rec["sc"]); got != "[openid billing:read billing:write]" {
		t.Fatalf("target scopes = %s, want the requested ones", got)
	}
}

func TestLogin_UnsafeReturnTo_UsesPostLoginRedirect(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.seedSource(nil)
	for _, rt := range []string{"https://evil.example.com", "//evil.example.com", `/\evil.example.com`} {
		h.mr.FlushAll()
		cookie = h.seedSource(nil)
		resp := immediate(t, h.call("/login", "GET", "/billing/v1/login?returnTo="+url.QueryEscape(rt), cookie))
		if resp.Headers["location"] != "/billing/v1/" {
			t.Errorf("returnTo %q: location = %q", rt, resp.Headers["location"])
		}
	}
}

func TestLogin_PassesThroughWithoutUsableSource(t *testing.T) {
	cases := map[string]func(h *harness) string{
		"no cookie": func(h *harness) string { return "" },
		"forged cookie": func(h *harness) string {
			h.seedSource(nil)
			return sourceCookie + "=" + randomSID() + ".bad-signature"
		},
		"duplicate cookie": func(h *harness) string {
			c := h.seedSource(nil)
			return c + "; " + c
		},
		"unknown session":  func(h *harness) string { return sourceCookie + "=" + cookieFor(sourceSigning, randomSID()) },
		"no device_secret": func(h *harness) string { return h.seedSource(map[string]interface{}{"device_secret": nil}) },
		"no id_token":      func(h *harness) string { return h.seedSource(map[string]interface{}{"it": nil}) },
		"absolute timeout": func(h *harness) string {
			return h.seedSource(map[string]interface{}{"cat": h.clock.Add(-9 * time.Hour).Unix()})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			cookie := setup(h)
			assertPass(t, h.call("/login", "GET", "/billing/v1/login", cookie))
			if n := h.idp.calls.Load(); n != 0 {
				t.Fatalf("token endpoint called %d times", n)
			}
		})
	}
}

func TestLogin_SourceUnderOtherKey_PassesThrough(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"source": map[string]interface{}{
		"cookieName":         sourceCookie,
		"sessionSigningKey":  sourceSigning,
		"tokenEncryptionKey": "a-different-encryption-secret-0123456789",
	}})
	assertPass(t, h.call("/login", "GET", "/billing/v1/login", h.seedSource(nil)))
	if h.idp.calls.Load() != 0 {
		t.Fatal("token endpoint must not be called")
	}
}

func TestLogin_ExchangeFailures_PassThroughWithoutSession(t *testing.T) {
	cases := map[string]func(h *harness){
		"rejected":         func(h *harness) { h.idp.status.Store(http.StatusBadRequest) },
		"other idp sid":    func(h *harness) { h.idp.idTokenSid = "idp-session-2" },
		"unavailable idp":  func(h *harness) { h.idp.status.Store(http.StatusServiceUnavailable) },
		"id_token missing": func(h *harness) { h.idp.idTokenSid = "" },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, map[string]interface{}{"tokenRequestMaxRetries": 0})
			setup(h)
			cookie := h.seedSource(nil)
			if name == "id_token missing" {
				// An IdP session ID is optional, but a configured issuer requires an id_token.
				h.idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "x"})
				})
			}
			assertPass(t, h.call("/login", "GET", "/billing/v1/login", cookie))
			if keys := h.sessionKeys(); len(keys) != 1 {
				t.Fatalf("session records = %d, want only the source", len(keys))
			}
		})
	}
}

func TestLogin_ExistingTargetSession_PassesThrough(t *testing.T) {
	h := newHarness(t, nil)
	cookie := h.seedSource(nil)
	first := immediate(t, h.call("/login", "GET", "/billing/v1/login", cookie))
	pair, _, _ := strings.Cut(first.Headers["set-cookie"], ";")

	assertPass(t, h.call("/login", "GET", "/billing/v1/login", cookie+"; "+pair))
	if n := h.idp.calls.Load(); n != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", n)
	}

	// A target cookie whose session has ended no longer blocks SSO.
	h.mr.Del(sessKey(targetSID(t, first.Headers["set-cookie"])))
	h.mr.Del(testPrefix + "sso:" + hashID(mustSourceSID(cookie)+"\x00billing-web\x00"+targetCookie))
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", cookie+"; "+pair))
	if resp.StatusCode != http.StatusFound || h.idp.calls.Load() != 2 {
		t.Fatalf("expected a new exchange, status %d calls %d", resp.StatusCode, h.idp.calls.Load())
	}
}

func mustSourceSID(cookie string) string {
	v, _, _ := strings.Cut(strings.TrimPrefix(cookie, sourceCookie+"="), ";")
	sid, _, _ := strings.Cut(v, ".")
	return sid
}

func TestLogin_NonGet_PassesThrough(t *testing.T) {
	h := newHarness(t, nil)
	assertPass(t, h.call("/login", "POST", "/billing/v1/login", h.seedSource(nil)))
}

func TestProtected_TransparentDisabled_PassesThrough(t *testing.T) {
	h := newHarness(t, nil)
	assertPass(t, h.call("/invoices", "GET", "/billing/v1/invoices", h.seedSource(nil)))
	if h.idp.calls.Load() != 0 {
		t.Fatal("token endpoint must not be called")
	}
}

func TestProtected_Transparent_RedirectsToSamePath(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"transparentSso": true})
	cookie := h.seedSource(nil)

	resp := immediate(t, h.call("/invoices", "POST", "/billing/v1/invoices?page=2", cookie))
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Headers["location"] != "/billing/v1/invoices?page=2" {
		t.Fatalf("response = %d %v", resp.StatusCode, resp.Headers)
	}
	sid := targetSID(t, resp.Headers["set-cookie"])

	// With the target cookie the request is oauth2-session's.
	pair, _, _ := strings.Cut(resp.Headers["set-cookie"], ";")
	assertPass(t, h.call("/invoices", "POST", "/billing/v1/invoices?page=2", cookie+"; "+pair))

	// A browser that keeps coming back without it gets the same session, then is let through.
	for i := 2; i <= maxTransparentRedirects; i++ {
		again := immediate(t, h.call("/invoices", "GET", "/billing/v1/invoices", cookie))
		if targetSID(t, again.Headers["set-cookie"]) != sid {
			t.Fatal("a repeated request must reuse the session just created")
		}
	}
	assertPass(t, h.call("/invoices", "GET", "/billing/v1/invoices", cookie))
	if n := h.idp.calls.Load(); n != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", n)
	}
}

func TestConcurrentRequests_ExchangeOnce(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.delay = 200 * time.Millisecond
	cookie := h.seedSource(nil)

	const n = 6
	sids := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, ok := h.call("/login", "GET", "/billing/v1/login", cookie).(policy.ImmediateResponse)
			if ok {
				sids[i] = targetSID(t, resp.Headers["set-cookie"])
			}
		}()
	}
	wg.Wait()
	for i, s := range sids {
		if s == "" || s != sids[0] {
			t.Fatalf("request %d got session %q, request 0 got %q", i, s, sids[0])
		}
	}
	if calls := h.idp.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls)
	}
}

func TestTargetSession_NeverOutlivesSource(t *testing.T) {
	h := newHarness(t, nil)
	// The source logged in 7h ago: 1h of its 8h absolute lifetime is left.
	cookie := h.seedSource(map[string]interface{}{"cat": h.clock.Add(-7 * time.Hour).Unix()})
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", cookie))
	if !strings.Contains(resp.Headers["set-cookie"], "Max-Age=3600") {
		t.Fatalf("set-cookie = %q, want Max-Age=3600", resp.Headers["set-cookie"])
	}
	sid := targetSID(t, resp.Headers["set-cookie"])
	raw, _ := h.mr.Get(sessKey(sid))
	rec := openRecord(t, targetEncryption, sessKey(sid), []byte(raw))
	if got := int64(rec["cat"].(float64)); got != h.clock.Add(-7*time.Hour).Unix() {
		t.Fatalf("target cat = %d, want it moved back to end with the source", got)
	}
	if ttl := h.mr.TTL(sessKey(sid)); ttl != 30*time.Minute {
		t.Fatalf("TTL = %v", ttl)
	}
}

func TestClientSecretPost(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"clientAuthMethod": "client_secret_post"})
	h.idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, _, ok := r.BasicAuth(); ok || r.PostForm.Get("client_id") != "billing-web" || r.PostForm.Get("client_secret") != "billing-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "x", "id_token": idToken("billing-web", "idp-session-1")})
	})
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", h.seedSource(nil)))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestTokenEndpointRedirect_NotFollowed(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"tokenRequestMaxRetries": 0})
	var followed atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	t.Cleanup(other.Close)
	h.idp.srv.Config.Handler = http.RedirectHandler(other.URL, http.StatusTemporaryRedirect)
	assertPass(t, h.call("/login", "GET", "/billing/v1/login", h.seedSource(nil)))
	if followed.Load() {
		t.Fatal("the token endpoint's redirect was followed")
	}
}

func TestLogin_SendsConfiguredResource(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"resource": "https://billing.example.com/api"})
	src := h.seedSource(nil)
	resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", src))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.Body)
	}
	h.idp.mu.Lock()
	got := h.idp.lastForm.Get("resource")
	h.idp.mu.Unlock()
	if got != "https://billing.example.com/api" {
		t.Fatalf("resource = %q", got)
	}
}

func TestLogin_ExchangeLayouts(t *testing.T) {
	const jwt = "urn:ietf:params:oauth:token-type:jwt"
	cases := map[string]struct {
		params map[string]interface{}
		want   map[string]string // "" = must not be sent
	}{
		"device_secret subject, id_token actor": {
			map[string]interface{}{"subjectToken": "device_secret", "subjectTokenType": jwt},
			map[string]string{
				"subject_token": "ds-1", "subject_token_type": jwt,
				"actor_token": idToken("orders-web", "idp-session-1"), "actor_token_type": TokenTypeIDToken,
			},
		},
		"device_secret subject, no actor": {
			map[string]interface{}{"subjectToken": "device_secret", "subjectTokenType": jwt, "actorToken": "none"},
			map[string]string{"subject_token": "ds-1", "subject_token_type": jwt, "actor_token": "", "actor_token_type": ""},
		},
		"spec layout with a jwt actor type": {
			map[string]interface{}{"actorTokenType": jwt},
			map[string]string{
				"subject_token": idToken("orders-web", "idp-session-1"), "subject_token_type": TokenTypeIDToken,
				"actor_token": "ds-1", "actor_token_type": jwt,
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tc.params)
			resp := immediate(t, h.call("/login", "GET", "/billing/v1/login", h.seedSource(nil)))
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, body %s", resp.StatusCode, resp.Body)
			}
			h.idp.mu.Lock()
			form := h.idp.lastForm
			h.idp.mu.Unlock()
			for k, v := range tc.want {
				if _, sent := form[k]; v == "" && sent {
					t.Errorf("%s must not be sent", k)
				} else if v != "" && form.Get(k) != v {
					t.Errorf("form %s = %q, want %q", k, form.Get(k), v)
				}
			}
		})
	}
}
