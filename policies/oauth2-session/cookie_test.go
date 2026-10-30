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
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestNewRandomID_IsUniqueAndFullLength(t *testing.T) {
	a, err := newRandomID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newRandomID()
	if a == b {
		t.Fatal("two random ids are equal")
	}
	if len(a) != encodedIDLength {
		t.Fatalf("id length = %d, want %d", len(a), encodedIDLength)
	}
}

func TestVerifySessionCookie_AcceptsOwnSignature(t *testing.T) {
	sid, _ := newRandomID()
	got, ok := verifySessionCookie(testKey, sessionCookieValue(testKey, sid))
	if !ok || got != sid {
		t.Fatalf("verify = (%q, %v), want (%q, true)", got, ok, sid)
	}
}

func TestVerifySessionCookie_RejectsTamperedOrMalformed(t *testing.T) {
	sid, _ := newRandomID()
	valid := sessionCookieValue(testKey, sid)
	otherSID, _ := newRandomID()

	cases := map[string]string{
		"empty":            "",
		"no signature":     sid,
		"wrong key":        sessionCookieValue([]byte("another-key-another-key-another!!"), sid),
		"swapped sid":      otherSID + valid[len(sid):],
		"flipped sig byte": valid[:len(valid)-1] + flip(valid[len(valid)-1]),
		"short sid":        sessionCookieValue(testKey, "abc"),
		"non-base64 sid":   sessionCookieValue(testKey, strings.Repeat("*", encodedIDLength)),
	}
	for name, value := range cases {
		if _, ok := verifySessionCookie(testKey, value); ok {
			t.Errorf("%s: verify accepted %q", name, value)
		}
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestSingleCookieValue(t *testing.T) {
	h := policy.NewHeaders(map[string][]string{"Cookie": {"a=1; X-ABC=v1", "b=2"}})
	if v, ok := singleCookieValue(h, "X-ABC"); !ok || v != "v1" {
		t.Fatalf("single cookie = (%q, %v)", v, ok)
	}
	if _, ok := singleCookieValue(h, "x-abc"); ok {
		t.Fatal("cookie names must be matched case-sensitively")
	}

	dup := policy.NewHeaders(map[string][]string{"Cookie": {"X-ABC=v1; X-ABC=v2"}})
	if _, ok := singleCookieValue(dup, "X-ABC"); ok {
		t.Fatal("duplicate cookies must not be trusted")
	}
	if _, ok := singleCookieValue(nil, "X-ABC"); ok {
		t.Fatal("nil headers must yield no cookie")
	}
}

func TestStripCookies(t *testing.T) {
	remaining, removed := stripCookies([]string{"a=1; X-ABC=s; X-ABC-state=t", "b=2"}, "X-ABC", "X-ABC-state")
	if !removed || remaining != "a=1; b=2" {
		t.Fatalf("strip = (%q, %v)", remaining, removed)
	}
	remaining, removed = stripCookies([]string{"X-ABC=s"}, "X-ABC")
	if !removed || remaining != "" {
		t.Fatalf("strip only cookie = (%q, %v)", remaining, removed)
	}
	if _, removed = stripCookies([]string{"a=1"}, "X-ABC"); removed {
		t.Fatal("nothing should be removed")
	}
}

func TestBuildSetCookie(t *testing.T) {
	got := buildSetCookie("X-ABC", "v", 90*time.Second, SameSiteLax, true)
	want := "X-ABC=v; Path=/; Max-Age=90; HttpOnly; Secure; SameSite=Lax"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = buildSetCookie("X-ABC", "v", 0, SameSiteStrict, false)
	want = "X-ABC=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
	if got != want {
		t.Fatalf("deletion cookie: got %q, want %q", got, want)
	}
}

func TestIsSafeRelativePath(t *testing.T) {
	safe := []string{"/", "/orders/v1/", "/orders/v1/orders/42?tab=items", "/a#frag"}
	for _, p := range safe {
		if !isSafeRelativePath(p) {
			t.Errorf("%q should be accepted", p)
		}
	}
	unsafe := []string{
		"", "orders", "//evil.com", "///evil.com", "/\\evil.com", "https://evil.com",
		"javascript:alert(1)", "/a\nb", "/a\tb", "/" + strings.Repeat("a", maxReturnToLength),
	}
	for _, p := range unsafe {
		if isSafeRelativePath(p) {
			t.Errorf("%q should be rejected", p)
		}
	}
}
