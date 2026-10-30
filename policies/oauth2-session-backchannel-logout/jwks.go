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
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// maxJWKSBytes bounds how much of a JWKS response is read.
	maxJWKSBytes = 1 << 20

	// minRefetchInterval rate-limits JWKS refetches triggered by an unknown kid, so a stream of
	// tokens with made-up kids can't be turned into a stream of requests to the IdP.
	minRefetchInterval = 10 * time.Second

	// minRSAModulusBits rejects RSA keys too short to trust.
	minRSAModulusBits = 2048
)

var errUnknownKey = errors.New("no matching key in the identity provider's JWKS")

// jwk is the subset of an RFC 7517 JSON Web Key this policy reads.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type namedKey struct {
	kid string
	key crypto.PublicKey
}

// jwksCache holds the identity provider's signing keys, fetched from jwksUri and refreshed when
// they are older than ttl or when a token names a kid the cache doesn't know (key rotation).
type jwksCache struct {
	uri    string
	ttl    time.Duration
	client *http.Client
	now    func() time.Time

	mu          sync.Mutex
	keys        []namedKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newJWKSCache(uri string, ttl, timeout time.Duration) *jwksCache {
	return &jwksCache{
		uri: uri,
		ttl: ttl,
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
			// jwksUri is the exact key endpoint; a redirect elsewhere is not followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}
}

// key returns the public key for kid. The lock is held across a fetch on purpose: back-channel
// logout requests are rare, and serializing them means concurrent tokens trigger one fetch.
func (c *jwksCache) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if c.keys != nil && now.Sub(c.fetchedAt) < c.ttl {
		if k, ok := c.lookup(kid); ok {
			return k, nil
		}
		if now.Sub(c.lastAttempt) < minRefetchInterval {
			return nil, errUnknownKey
		}
	}

	c.lastAttempt = now
	keys, err := c.fetch(ctx)
	if err != nil {
		// Keep serving the keys we have; a failed fetch shouldn't break logout for known keys.
		if k, ok := c.lookup(kid); ok {
			return k, nil
		}
		return nil, err
	}
	c.keys, c.fetchedAt = keys, now
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	return nil, errUnknownKey
}

// lookup finds kid. A token without a kid is accepted only when the JWKS has exactly one key.
func (c *jwksCache) lookup(kid string) (crypto.PublicKey, bool) {
	if kid == "" {
		if len(c.keys) == 1 {
			return c.keys[0].key, true
		}
		return nil, false
	}
	for _, k := range c.keys {
		if k.kid == kid {
			return k.key, true
		}
	}
	return nil, false
}

func (c *jwksCache) fetch(ctx context.Context) ([]namedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("JWKS response exceeded %d bytes", maxJWKSBytes)
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}
	var keys []namedKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue // skip keys we can't use; the rest of the set is still valid
		}
		keys = append(keys, namedKey{kid: k.Kid, key: pub})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable signing keys")
	}
	return keys, nil
}

// TODO(pqc): migrate - RSA and ECDSA verification is what identity providers sign logout
// tokens with today; add ML-DSA once IdPs publish ML-DSA keys in their JWKS.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeB64URL(k.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeB64URL(k.E)
		if err != nil {
			return nil, err
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e)
		if modulus.BitLen() < minRSAModulusBits {
			return nil, fmt.Errorf("RSA key shorter than %d bits", minRSAModulusBits)
		}
		if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil

	case "EC":
		var curve elliptic.Curve
		var ecdhCurve ecdh.Curve
		switch k.Crv {
		case "P-256":
			curve, ecdhCurve = elliptic.P256(), ecdh.P256()
		case "P-384":
			curve, ecdhCurve = elliptic.P384(), ecdh.P384()
		case "P-521":
			curve, ecdhCurve = elliptic.P521(), ecdh.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := decodeB64URL(k.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeB64URL(k.Y)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, fmt.Errorf("EC coordinate too long")
		}
		// Reject points not on the curve (uncompressed form: 0x04 || x || y).
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1+size-len(x):1+size], x)
		copy(point[1+2*size-len(y):], y)
		if _, err := ecdhCurve.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("EC point is not on curve %q", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func decodeB64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("invalid base64url value")
	}
	return b, nil
}
