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

package backchannellogout

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
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
	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	testIssuer   = "https://idp.example.com"
	testClientID = "orders-web"
	testPrefix   = "oauth2-session:v1:"
)

// rsaKey is generated once; 2048-bit generation is slow enough to matter per test.
var (
	rsaKeyOnce sync.Once
	rsaKey     *rsa.PrivateKey
	rsaKey2    *rsa.PrivateKey
)

func testRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaKeyOnce.Do(func() {
		rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		rsaKey2, _ = rsa.GenerateKey(rand.Reader, 2048)
	})
	return rsaKey, rsaKey2
}

// fakeJWKS serves a mutable key set.
type fakeJWKS struct {
	srv     *httptest.Server
	mu      sync.Mutex
	keys    []map[string]string
	fetches atomic.Int32
}

func newFakeJWKS(t *testing.T) *fakeJWKS {
	f := &fakeJWKS{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.fetches.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": f.keys})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeJWKS) setRSA(kid string, pub *rsa.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, map[string]string{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	})
}

func (f *fakeJWKS) setEC(kid string, pub *ecdsa.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	size := (pub.Curve.Params().BitSize + 7) / 8
	f.keys = append(f.keys, map[string]string{
		"kty": "EC", "kid": kid, "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
		"y": base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
	})
}

type harness struct {
	t     *testing.T
	pol   *Policy
	mr    *miniredis.Miniredis
	jwks  *fakeJWKS
	clock time.Time
	jtis  int
}

func newHarness(t *testing.T, overrides map[string]interface{}) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	jwks := newFakeJWKS(t)
	key, _ := testRSAKeys(t)
	jwks.setRSA("key-1", &key.PublicKey)

	host, port, _ := strings.Cut(mr.Addr(), ":")
	portNum, _ := strconv.Atoi(port)
	params := map[string]interface{}{
		"issuer":   testIssuer,
		"jwksUri":  jwks.srv.URL,
		"clientId": testClientID,
		"redis":    map[string]interface{}{"host": host, "port": portNum},
	}
	for k, v := range overrides {
		params[k] = v
	}
	pp, err := GetPolicy(policy.PolicyMetadata{RouteName: "test"}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	h := &harness{t: t, pol: pp.(*Policy), mr: mr, jwks: jwks, clock: time.Unix(1_800_000_000, 0)}
	h.pol.now = func() time.Time { return h.clock }
	h.pol.jwks.now = func() time.Time { return h.clock }
	return h
}

// claims returns valid logout token claims; tests change them to break one rule at a time.
func (h *harness) claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":    testIssuer,
		"aud":    testClientID,
		"iat":    h.clock.Unix(),
		"jti":    h.nextJTI(),
		"sid":    "idp-session-1",
		"sub":    "user-1",
		"events": map[string]interface{}{backchannelLogoutEvent: map[string]interface{}{}},
	}
}

func (h *harness) nextJTI() string {
	h.jtis++
	return "jti-" + strconv.Itoa(h.jtis)
}

func signRS256(t *testing.T, claims jwt.MapClaims, kid string, key *rsa.PrivateKey) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (h *harness) post(body, contentType string) policy.ImmediateResponse {
	h.t.Helper()
	headers := map[string][]string{}
	if contentType != "" {
		headers["content-type"] = []string{contentType}
	}
	rc := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(headers),
		Body:          &policy.Body{Content: []byte(body), EndOfStream: true, Present: body != ""},
		Method:        http.MethodPost,
	}
	resp, ok := h.pol.OnRequestBody(context.Background(), rc, nil).(policy.ImmediateResponse)
	if !ok {
		h.t.Fatal("expected an ImmediateResponse")
	}
	return resp
}

func (h *harness) logout(token string) policy.ImmediateResponse {
	return h.post("logout_token="+url.QueryEscape(token), "application/x-www-form-urlencoded")
}

// seedSession writes a session and its index entries exactly as oauth2-session does.
func (h *harness) seedSession(member, sid, sub string) string {
	sessKey := testPrefix + "sess:" + member
	_ = h.mr.Set(sessKey, "ciphertext")
	if sid != "" {
		_, _ = h.mr.SAdd(indexKey(testPrefix, "sid", testIssuer, sid), member)
	}
	if sub != "" {
		_, _ = h.mr.SAdd(indexKey(testPrefix, "sub", testIssuer, sub), member)
	}
	return sessKey
}

func assertStatus(t *testing.T, resp policy.ImmediateResponse, status int, errCode string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, status, resp.Body)
	}
	if resp.Headers["cache-control"] != "no-store" {
		t.Fatalf("cache-control = %q", resp.Headers["cache-control"])
	}
	if errCode != "" && string(resp.Body) != `{"error":"`+errCode+`"}` {
		t.Fatalf("body = %s, want error %q", resp.Body, errCode)
	}
}

// TestIndexKeyFormat pins the key format shared with oauth2-session; its TestIdpIndexKeyFormat
// asserts the same literal. Change both together or back-channel logout stops finding sessions.
func TestIndexKeyFormat(t *testing.T) {
	got := indexKey(testPrefix, "sid", testIssuer, "idp-session-1")
	want := "oauth2-session:v1:idp-sid:a8d87ebcd6fd2b62d66b060dfaf245b72775ae073c48fbd7fb60e38eb4a2c72c"
	if got != want {
		t.Fatalf("index key = %q, want %q", got, want)
	}
	if hashID("gateway-session-id") != "882b20bf25845c594720ed7862e5d707d6a5ecfc753a22ac8e018231dfa26da4" {
		t.Fatal("session hash format changed")
	}
}

func TestLogout_BySidEndsOnlyThatIdPSession(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testRSAKeys(t)
	a := h.seedSession("aaa", "idp-session-1", "user-1")
	b := h.seedSession("bbb", "idp-session-1", "user-1")
	other := h.seedSession("ccc", "idp-session-2", "user-1")

	resp := h.logout(signRS256(t, h.claims(), "key-1", key))
	assertStatus(t, resp, http.StatusOK, "")
	if len(resp.Body) != 0 {
		t.Fatalf("success body should be empty, got %s", resp.Body)
	}
	if h.mr.Exists(a) || h.mr.Exists(b) {
		t.Fatal("sessions of the logged-out IdP session must be deleted")
	}
	if !h.mr.Exists(other) {
		t.Fatal("a session of another IdP session must be kept")
	}
	if h.mr.Exists(indexKey(testPrefix, "sid", testIssuer, "idp-session-1")) {
		t.Fatal("the index set must be deleted")
	}
}

func TestLogout_BySubEndsEverySessionOfTheUser(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testRSAKeys(t)
	a := h.seedSession("aaa", "idp-session-1", "user-1")
	b := h.seedSession("bbb", "idp-session-2", "user-1")
	other := h.seedSession("ccc", "idp-session-3", "user-2")

	claims := h.claims()
	delete(claims, "sid")
	assertStatus(t, h.logout(signRS256(t, claims, "key-1", key)), http.StatusOK, "")
	if h.mr.Exists(a) || h.mr.Exists(b) {
		t.Fatal("every session of the user must be deleted")
	}
	if !h.mr.Exists(other) {
		t.Fatal("another user's session must be kept")
	}
}

func TestLogout_UnknownSessionStillSucceeds(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testRSAKeys(t)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-1", key)), http.StatusOK, "")
}

func TestLogout_ReplayedTokenIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testRSAKeys(t)
	claims := h.claims()
	delete(claims, "sid") // a sub-only token: a replay would end the user's newer sessions
	token := signRS256(t, claims, "key-1", key)
	assertStatus(t, h.logout(token), http.StatusOK, "")

	newer := h.seedSession("ddd", "idp-session-9", "user-1")
	assertStatus(t, h.logout(token), http.StatusBadRequest, "invalid_request")
	if !h.mr.Exists(newer) {
		t.Fatal("a replayed token must not end sessions started after the logout")
	}
}

func TestLogout_RejectsInvalidTokens(t *testing.T) {
	h := newHarness(t, nil)
	key, otherKey := testRSAKeys(t)

	cases := map[string]func() string{
		"wrong issuer": func() string {
			c := h.claims()
			c["iss"] = "https://evil.example.com"
			return signRS256(t, c, "key-1", key)
		},
		"wrong audience": func() string {
			c := h.claims()
			c["aud"] = "someone-else"
			return signRS256(t, c, "key-1", key)
		},
		"signed by another key": func() string { return signRS256(t, h.claims(), "key-1", otherKey) },
		"missing events": func() string {
			c := h.claims()
			delete(c, "events")
			return signRS256(t, c, "key-1", key)
		},
		"event is not an object": func() string {
			c := h.claims()
			c["events"] = map[string]interface{}{backchannelLogoutEvent: "yes"}
			return signRS256(t, c, "key-1", key)
		},
		"contains nonce": func() string {
			c := h.claims()
			c["nonce"] = "n"
			return signRS256(t, c, "key-1", key)
		},
		"missing jti": func() string {
			c := h.claims()
			delete(c, "jti")
			return signRS256(t, c, "key-1", key)
		},
		"neither sid nor sub": func() string {
			c := h.claims()
			delete(c, "sid")
			delete(c, "sub")
			return signRS256(t, c, "key-1", key)
		},
		"missing iat": func() string {
			c := h.claims()
			delete(c, "iat")
			return signRS256(t, c, "key-1", key)
		},
		"too old": func() string {
			c := h.claims()
			c["iat"] = h.clock.Add(-7 * time.Minute).Unix()
			return signRS256(t, c, "key-1", key)
		},
		"issued in the future": func() string {
			c := h.claims()
			c["iat"] = h.clock.Add(5 * time.Minute).Unix()
			return signRS256(t, c, "key-1", key)
		},
		"expired": func() string {
			c := h.claims()
			c["exp"] = h.clock.Add(-5 * time.Minute).Unix()
			return signRS256(t, c, "key-1", key)
		},
		"HS256 with the public key as secret": func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, h.claims())
			tok.Header["kid"] = "key-1"
			s, _ := tok.SignedString(key.PublicKey.N.Bytes())
			return s
		},
		"alg none": func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, h.claims())
			s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			return s
		},
		"not a JWT": func() string { return "not-a-jwt" },
	}
	for name, makeToken := range cases {
		victim := h.seedSession("victim", "idp-session-1", "user-1")
		resp := h.logout(makeToken())
		if resp.StatusCode != http.StatusBadRequest || string(resp.Body) != `{"error":"invalid_request"}` {
			t.Errorf("%s: status %d body %s", name, resp.StatusCode, resp.Body)
		}
		if !h.mr.Exists(victim) {
			t.Errorf("%s: a rejected token must not end sessions", name)
		}
	}
}

func TestLogout_RejectsMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testRSAKeys(t)
	token := signRS256(t, h.claims(), "key-1", key)

	assertStatus(t, h.post("logout_token="+token, "application/json"), http.StatusBadRequest, "invalid_request")
	assertStatus(t, h.post("logout_token="+token, ""), http.StatusBadRequest, "invalid_request")
	assertStatus(t, h.post("", "application/x-www-form-urlencoded"), http.StatusBadRequest, "invalid_request")
	assertStatus(t, h.post("other=1", "application/x-www-form-urlencoded"), http.StatusBadRequest, "invalid_request")
	assertStatus(t, h.post("logout_token="+token+"&logout_token="+token, "application/x-www-form-urlencoded"), http.StatusBadRequest, "invalid_request")
	assertStatus(t, h.post("logout_token="+strings.Repeat("a", maxBodyBytes), "application/x-www-form-urlencoded"), http.StatusBadRequest, "invalid_request")

	rc := &policy.RequestContext{SharedContext: &policy.SharedContext{}, Headers: policy.NewHeaders(nil), Method: http.MethodGet}
	resp := h.pol.OnRequestBody(context.Background(), rc, nil).(policy.ImmediateResponse)
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Headers["allow"] != "POST" {
		t.Fatalf("GET: status %d", resp.StatusCode)
	}

	// A charset parameter on the content type is fine.
	assertStatus(t, h.post("logout_token="+url.QueryEscape(token), "application/x-www-form-urlencoded; charset=UTF-8"), http.StatusOK, "")
}

func TestJWKS_KeyRotationAndCaching(t *testing.T) {
	h := newHarness(t, nil)
	key, newKey := testRSAKeys(t)

	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-1", key)), http.StatusOK, "")
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-1", key)), http.StatusOK, "")
	if n := h.jwks.fetches.Load(); n != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 (cached)", n)
	}

	// The IdP rotates to key-2; the first token naming it triggers a refetch.
	h.jwks.setRSA("key-2", &newKey.PublicKey)
	h.clock = h.clock.Add(minRefetchInterval + time.Second)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-2", newKey)), http.StatusOK, "")
	if n := h.jwks.fetches.Load(); n != 2 {
		t.Fatalf("JWKS fetches = %d, want 2 after rotation", n)
	}

	// Unknown kids don't trigger a fetch more often than minRefetchInterval.
	h.clock = h.clock.Add(time.Second)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-unknown", newKey)), http.StatusBadRequest, "invalid_request")
	h.clock = h.clock.Add(time.Second)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-unknown-2", newKey)), http.StatusBadRequest, "invalid_request")
	if n := h.jwks.fetches.Load(); n != 2 {
		t.Fatalf("JWKS fetches = %d, want still 2 (rate-limited)", n)
	}
}

func TestLogout_ES256WhenAllowed(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"allowedAlgorithms": []interface{}{"ES256"}})
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.jwks.mu.Lock()
	h.jwks.keys = nil
	h.jwks.mu.Unlock()
	h.jwks.setEC("ec-1", &ecKey.PublicKey)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, h.claims())
	tok.Header["kid"] = "ec-1"
	s, _ := tok.SignedString(ecKey)
	assertStatus(t, h.logout(s), http.StatusOK, "")

	// RS256 is no longer allowed with this configuration.
	key, _ := testRSAKeys(t)
	h.clock = h.clock.Add(time.Second)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "ec-1", key)), http.StatusBadRequest, "invalid_request")
}

func TestLogout_RedisUnavailable(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"redis": map[string]interface{}{"host": "127.0.0.1", "port": 1}})
	key, _ := testRSAKeys(t)
	assertStatus(t, h.logout(signRS256(t, h.claims(), "key-1", key)), http.StatusBadRequest, "temporarily_unavailable")
}

func TestParseConfig_Rejects(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{"issuer": testIssuer, "jwksUri": "https://idp.example.com/jwks", "clientId": testClientID}
	}
	if _, err := parseConfig(base()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(map[string]interface{}){
		"missing issuer":   func(p map[string]interface{}) { delete(p, "issuer") },
		"missing clientId": func(p map[string]interface{}) { delete(p, "clientId") },
		"relative jwksUri": func(p map[string]interface{}) { p["jwksUri"] = "/jwks" },
		"jwksUri with credentials": func(p map[string]interface{}) {
			p["jwksUri"] = "https://u:p@idp.example.com/jwks"
		},
		"HS256 allowed": func(p map[string]interface{}) { p["allowedAlgorithms"] = []interface{}{"HS256"} },
		"none allowed":  func(p map[string]interface{}) { p["allowedAlgorithms"] = []interface{}{"none"} },
	}
	for name, mutate := range cases {
		p := base()
		mutate(p)
		if _, err := parseConfig(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
