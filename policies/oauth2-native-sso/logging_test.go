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
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of parallel exchanges.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs sends the policy's and token client's logs, at debug level, to a buffer.
func captureLogs(h *harness) *syncBuffer {
	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})).With("route", "test")
	h.pol.log = log
	h.pol.tokens.log = log
	return buf
}

// sidOf returns the session ID inside a "name=sid.sig; ..." cookie header.
func sidOf(t *testing.T, cookieHeader string) string {
	t.Helper()
	pair, _, _ := strings.Cut(cookieHeader, ";")
	_, value, _ := strings.Cut(pair, "=")
	sid, _, ok := strings.Cut(value, ".")
	if !ok {
		t.Fatalf("no session ID in %q", cookieHeader)
	}
	return sid
}

// TestDebugLogs_NeverContainPII drives every sign-in outcome with debug logging on and checks
// that no session ID, cookie value, token, device_secret, user claim, client secret, IdP error
// description or request path/query reaches the log, while the diagnostic fields do.
func TestDebugLogs_NeverContainPII(t *testing.T) {
	forbidden := []string{
		"orders-at", "orders-rt", "billing-at", "billing-rt", // access and refresh tokens
		"ds-1", "ds-2", // device secrets
		"user-1", "idp-session-1", // sub and sid claims
		"billing-secret", sourceSigning, sourceEncryption, targetSigning, targetEncryption,
		"device_secret revoked",    // the IdP's error_description
		"alice@example.com", "ssn", // request path and query
	}
	var logs strings.Builder
	var sessionIDs []string

	// 1. Successful login with device_secret rotation and a returnTo carrying user data.
	h := newHarness(t, nil)
	buf := captureLogs(h)
	cookie := h.seedSource(nil)
	sessionIDs = append(sessionIDs, sidOf(t, cookie), strings.SplitN(strings.SplitN(cookie, "=", 2)[1], ";", 2)[0])
	resp := immediate(t, h.call("/login", http.MethodGet, "/login?returnTo=%2Fusers%2Falice%40example.com%3Fssn%3D1", cookie))
	sessionIDs = append(sessionIDs, targetSID(t, resp.Headers["set-cookie"]))
	sessionIDs = append(sessionIDs, strings.SplitN(resp.Headers["set-cookie"], ";", 2)[0])
	logs.WriteString(buf.String())
	for _, want := range []string{
		"sourceSessionRef=", "targetSessionRef=", "hasDeviceSecret=true", "deviceSecretRotated=true",
		"token endpoint answered 200", "issuerMatches=true", "written=true", "location=returnTo",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("success logs lack %q:\n%s", want, buf.String())
		}
	}

	// 2. Source session without a device_secret: the reason is logged at info.
	h = newHarness(t, nil)
	buf = captureLogs(h)
	cookie = h.seedSource(map[string]interface{}{"device_secret": nil})
	sessionIDs = append(sessionIDs, sidOf(t, cookie))
	assertPass(t, h.call("/login", http.MethodGet, "/login", cookie))
	logs.WriteString(buf.String())
	if !strings.Contains(buf.String(), "level=INFO") || !strings.Contains(buf.String(), "has no device_secret") {
		t.Errorf("missing device_secret is not explained:\n%s", buf.String())
	}

	// 3. The IdP rejects the exchange with an error_description.
	h = newHarness(t, nil)
	buf = captureLogs(h)
	h.idp.status.Store(http.StatusBadRequest)
	cookie = h.seedSource(nil)
	sessionIDs = append(sessionIDs, sidOf(t, cookie))
	assertPass(t, h.call("/login", http.MethodGet, "/login", cookie))
	logs.WriteString(buf.String())
	if !strings.Contains(buf.String(), "invalid_grant") {
		t.Errorf("the sanitised OAuth error code is not logged:\n%s", buf.String())
	}

	// 4. A forged source cookie and a transparent request on a path carrying user data.
	h = newHarness(t, map[string]interface{}{"transparentSso": true})
	buf = captureLogs(h)
	assertPass(t, h.call("/login", http.MethodGet, "/login", sourceCookie+"=forged-sid.forged-sig"))
	cookie = h.seedSource(nil)
	sessionIDs = append(sessionIDs, sidOf(t, cookie))
	immediate(t, h.call("/users/{id}", http.MethodGet, "/users/alice@example.com?ssn=1", cookie))
	logs.WriteString(buf.String())
	for _, want := range []string{"bad signature or format", "operation=/users/{id}", "transparent redirect count"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("logs lack %q:\n%s", want, buf.String())
		}
	}

	all := logs.String()
	for _, s := range append(forbidden, append(sessionIDs, "forged-sid", "forged-sig")...) {
		if s != "" && strings.Contains(all, s) {
			t.Errorf("logs contain %q:\n%s", s, all)
		}
	}
}
