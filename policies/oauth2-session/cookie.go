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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// randomIDBytes is the entropy of session IDs and state values: 256 bits.
	randomIDBytes = 32

	// maxReturnToLength bounds a browser-supplied returnTo before it is stored in Redis.
	maxReturnToLength = 2048
)

// encodedIDLength is the base64url (unpadded) length of a randomIDBytes value.
var encodedIDLength = base64.RawURLEncoding.EncodedLen(randomIDBytes)

// newRandomID returns 256 random bits from crypto/rand, base64url-encoded.
func newRandomID() (string, error) {
	b := make([]byte, randomIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newSHA3() hash.Hash { return sha3.New256() }

// signID returns the base64url HMAC-SHA3-256 tag of id under key.
func signID(key []byte, id string) string {
	mac := hmac.New(newSHA3, key)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sessionCookieValue builds the "sid.sig" cookie value.
func sessionCookieValue(key []byte, sid string) string {
	return sid + "." + signID(key, sid)
}

// verifySessionCookie returns the session ID carried by a "sid.sig" value, or false when the
// value is malformed or the signature doesn't match. Signature comparison is constant time, so
// a forged cookie is rejected without revealing how much of it matched - and without a Redis call.
func verifySessionCookie(key []byte, value string) (string, bool) {
	idx := strings.LastIndexByte(value, '.')
	if idx < 0 {
		return "", false
	}
	sid, sig := value[:idx], value[idx+1:]
	if len(sid) != encodedIDLength {
		return "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(sid); err != nil {
		return "", false
	}
	if !hmac.Equal([]byte(sig), []byte(signID(key, sid))) {
		return "", false
	}
	return sid, true
}

// constantTimeEqual compares two strings without leaking where they differ.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// cookieValues returns every value sent for the cookie named exactly name. Cookie names are
// case-sensitive (RFC 6265), so no case folding is applied.
func cookieValues(headers *policy.Headers, name string) []string {
	if headers == nil {
		return nil
	}
	var out []string
	for _, raw := range headers.Get("cookie") {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			idx := strings.IndexByte(part, '=')
			if idx < 0 {
				continue
			}
			if strings.TrimSpace(part[:idx]) == name {
				out = append(out, strings.Trim(strings.TrimSpace(part[idx+1:]), `"`))
			}
		}
	}
	return out
}

// singleCookieValue returns the cookie's value only when exactly one was sent. Two cookies of the
// same name usually mean one was planted from a sibling subdomain, so neither is trusted.
func singleCookieValue(headers *policy.Headers, name string) (string, bool) {
	vals := cookieValues(headers, name)
	if len(vals) != 1 || vals[0] == "" {
		return "", false
	}
	return vals[0], true
}

// stripCookies removes the named cookies from Cookie header values. It returns the remaining
// Cookie header and whether anything was removed.
func stripCookies(cookieHeaderValues []string, names ...string) (string, bool) {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	parts := make([]string, 0, 8)
	removed := false
	for _, raw := range cookieHeaderValues {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if idx := strings.IndexByte(part, '='); idx >= 0 && drop[strings.TrimSpace(part[:idx])] {
				removed = true
				continue
			}
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "; "), removed
}

// buildSetCookie formats a Set-Cookie header value. Cookies are always host-only (no Domain),
// scoped to Path=/ and HttpOnly. A maxAge <= 0 produces a deletion cookie.
func buildSetCookie(name, value string, maxAge time.Duration, sameSite string, secure bool) string {
	seconds := int64(maxAge / time.Second)
	if seconds <= 0 {
		value = ""
		seconds = 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s=%s; Path=/; Max-Age=%d; HttpOnly", name, value, seconds)
	if secure {
		b.WriteString("; Secure")
	}
	b.WriteString("; SameSite=")
	b.WriteString(sameSite)
	return b.String()
}

// isSafeRelativePath reports whether p is a same-origin path the gateway may redirect to: it
// starts with a single '/', has no scheme, host or backslash (browsers treat '\' like '/', so
// "/\evil.com" would become protocol-relative), and contains no control characters.
func isSafeRelativePath(p string) bool {
	if p == "" || len(p) > maxReturnToLength || p[0] != '/' {
		return false
	}
	if strings.HasPrefix(p, "//") || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	return true
}
