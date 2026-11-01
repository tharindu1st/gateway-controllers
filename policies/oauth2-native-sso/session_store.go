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
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// deviceSecretField is the JSON member of an oauth2-session record that holds the Native SSO
// device_secret.
const deviceSecretField = "device_secret"

// targetSession is the record written for the target API. Its JSON tags are oauth2-session's
// session struct (policies/oauth2-session/session_store.go) plus device_secret; the target's
// oauth2-session policy reads it as one of its own sessions.
type targetSession struct {
	AccessToken  string   `json:"at"`
	RefreshToken string   `json:"rt,omitempty"`
	TokenType    string   `json:"tt,omitempty"`
	IDToken      string   `json:"it,omitempty"`
	Scopes       []string `json:"sc,omitempty"`
	ExpiresAt    int64    `json:"exp"`
	CreatedAt    int64    `json:"cat"`
	ObtainedAt   int64    `json:"oat,omitempty"`
	DeviceSecret string   `json:"device_secret,omitempty"`
}

// sourceSession is the part of the source API's oauth2-session record the exchange needs.
type sourceSession struct {
	IDToken      string `json:"it"`
	DeviceSecret string `json:"device_secret"`
	CreatedAt    int64  `json:"cat"`
}

// handoff is what the request that ran the exchange leaves for concurrent requests of the same
// browser: the target session ID and its login time, sealed with the target key.
type handoff struct {
	SID       string `json:"sid"`
	CreatedAt int64  `json:"cat"`
}

// releaseLockScript deletes the lock only if it still holds this caller's token.
var releaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0`)

// sessionStore reads source sessions and writes target sessions in oauth2-session's Redis layout.
// Session keys are built from a SHA3-256 hash of the session ID, exactly as oauth2-session builds
// them; records are AES-256-GCM sealed with the Redis key as additional data.
type sessionStore struct {
	client       *redis.Client
	prefix       string
	sourceAEAD   cipher.AEAD
	targetAEAD   cipher.AEAD
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // 32-byte key: AES-256
	if err != nil {
		return nil, fmt.Errorf("creating token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating token cipher: %w", err)
	}
	return aead, nil
}

func newSessionStore(client *redis.Client, rp redisParams, sourceKey, targetKey []byte) (*sessionStore, error) {
	src, err := newAEAD(sourceKey)
	if err != nil {
		return nil, err
	}
	tgt, err := newAEAD(targetKey)
	if err != nil {
		return nil, err
	}
	return &sessionStore{
		client:       client,
		prefix:       rp.keyPrefix,
		sourceAEAD:   src,
		targetAEAD:   tgt,
		readTimeout:  rp.readTimeout,
		writeTimeout: rp.writeTimeout,
	}, nil
}

func hashID(id string) string {
	sum := sha3.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// sessionKey must match oauth2-session's sessionStore.sessionKey.
func (s *sessionStore) sessionKey(sid string) string { return s.prefix + "sess:" + hashID(sid) }

// idpIndexKey must match oauth2-session's sessionStore.idpIndexKey and the key the
// oauth2-session-backchannel-logout policy builds.
func (s *sessionStore) idpIndexKey(kind, issuer, value string) string {
	return s.prefix + "idp-" + kind + ":" + hashID(issuer+"\x00"+value)
}

// The SSO keys are scoped to one source session and one target (client, cookie).
func (s *sessionStore) ssoLockKey(scope string) string     { return s.prefix + "sso-lock:" + scope }
func (s *sessionStore) ssoHandoffKey(scope string) string  { return s.prefix + "sso:" + scope }
func (s *sessionStore) ssoRedirectKey(scope string) string { return s.prefix + "sso-redir:" + scope }

func seal(aead cipher.AEAD, key string, plain []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plain, []byte(key)), nil
}

func open(aead cipher.AEAD, key string, raw []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("record is truncated")
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], []byte(key))
	if err != nil {
		// Wrong key (e.g. a secret that doesn't match the oauth2-session attachment) or tampering.
		return nil, fmt.Errorf("decrypting record: %w", err)
	}
	return plain, nil
}

// loadSource reads the source session without touching its TTL, so SSO into the target never
// extends the source's idle timeout. It returns (nil, nil) when there is no such session.
func (s *sessionStore) loadSource(ctx context.Context, sid string) (*sourceSession, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	key := s.sessionKey(sid)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading source session: %w", err)
	}
	plain, err := open(s.sourceAEAD, key, raw)
	if err != nil {
		return nil, err
	}
	var src sourceSession
	if err := json.Unmarshal(plain, &src); err != nil {
		return nil, fmt.Errorf("decoding source session: %w", err)
	}
	return &src, nil
}

// targetSessionExists reports whether sid names a live target session.
func (s *sessionStore) targetSessionExists(ctx context.Context, sid string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	n, err := s.client.Exists(ctx, s.sessionKey(sid)).Result()
	if err != nil {
		return false, fmt.Errorf("checking target session: %w", err)
	}
	return n > 0, nil
}

// createTarget stores a new target session, adds it to the back-channel index sets and leaves the
// handoff record for concurrent requests, all in one MULTI/EXEC transaction.
func (s *sessionStore) createTarget(ctx context.Context, sid string, sess *targetSession, ttl time.Duration,
	indexKeys []string, indexTTL time.Duration, scope string, handoffTTL time.Duration) error {
	key := s.sessionKey(sid)
	plain, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("encoding target session: %w", err)
	}
	sealed, err := seal(s.targetAEAD, key, plain)
	if err != nil {
		return err
	}
	hk := s.ssoHandoffKey(scope)
	hplain, err := json.Marshal(handoff{SID: sid, CreatedAt: sess.CreatedAt})
	if err != nil {
		return fmt.Errorf("encoding handoff: %w", err)
	}
	hsealed, err := seal(s.targetAEAD, hk, hplain)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, key, sealed, ttl)
	member := hashID(sid)
	for _, ik := range indexKeys {
		pipe.SAdd(ctx, ik, member)
		pipe.Expire(ctx, ik, indexTTL)
	}
	pipe.Set(ctx, hk, hsealed, handoffTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("writing target session: %w", err)
	}
	return nil
}

// readHandoff returns the target session a concurrent request created for scope, if any.
func (s *sessionStore) readHandoff(ctx context.Context, scope string) (*handoff, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	key := s.ssoHandoffKey(scope)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading handoff: %w", err)
	}
	plain, err := open(s.targetAEAD, key, raw)
	if err != nil {
		return nil, err
	}
	var h handoff
	if err := json.Unmarshal(plain, &h); err != nil || h.SID == "" {
		return nil, fmt.Errorf("decoding handoff")
	}
	return &h, nil
}

// rotateSourceDeviceSecret replaces the source session's device_secret with the one the IdP
// rotated to. It runs as an optimistic transaction (WATCH), changes only that one JSON member -
// every other member, including ones this policy doesn't know, is kept byte for byte - and keeps
// the record's TTL. Nothing is written when the record is gone or no longer holds oldSecret.
func (s *sessionStore) rotateSourceDeviceSecret(ctx context.Context, sid, oldSecret, newSecret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout+s.writeTimeout)
	defer cancel()
	key := s.sessionKey(sid)
	changed := false
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		raw, err := tx.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return nil
		}
		if err != nil {
			return err
		}
		plain, err := open(s.sourceAEAD, key, raw)
		if err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(plain, &fields); err != nil {
			return fmt.Errorf("decoding source session: %w", err)
		}
		var current string
		if v, ok := fields[deviceSecretField]; ok {
			_ = json.Unmarshal(v, &current)
		}
		if current != oldSecret {
			return nil
		}
		enc, err := json.Marshal(newSecret)
		if err != nil {
			return err
		}
		fields[deviceSecretField] = enc
		updated, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		sealed, err := seal(s.sourceAEAD, key, updated)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.SetArgs(ctx, key, sealed, redis.SetArgs{Mode: "XX", KeepTTL: true})
			return nil
		})
		if err == nil {
			changed = true
		}
		return err
	}, key)
	if errors.Is(err, redis.TxFailedErr) {
		return false, nil // the record changed meanwhile, e.g. oauth2-session refreshed it
	}
	if err != nil {
		return false, fmt.Errorf("rotating device_secret: %w", err)
	}
	return changed, nil
}

// acquireLock takes the per-scope exchange lock (SET NX PX).
func (s *sessionStore) acquireLock(ctx context.Context, scope string, ttl time.Duration) (token string, ok bool, err error) {
	token, err = newRandomID()
	if err != nil {
		return "", false, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	ok, err = s.client.SetNX(ctx, s.ssoLockKey(scope), token, ttl).Result()
	if err != nil {
		return "", false, fmt.Errorf("acquiring sso lock: %w", err)
	}
	return token, ok, nil
}

func (s *sessionStore) releaseLock(ctx context.Context, scope, token string) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	if err := releaseLockScript.Run(ctx, s.client, []string{s.ssoLockKey(scope)}, token).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("releasing sso lock: %w", err)
	}
	return nil
}

func (s *sessionStore) lockHeld(ctx context.Context, scope string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	n, err := s.client.Exists(ctx, s.ssoLockKey(scope)).Result()
	if err != nil {
		return false, fmt.Errorf("checking sso lock: %w", err)
	}
	return n > 0, nil
}

// countRedirect counts transparent SSO redirects for scope within window and returns the count.
func (s *sessionStore) countRedirect(ctx context.Context, scope string, window time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	key := s.ssoRedirectKey(scope)
	n, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("counting sso redirects: %w", err)
	}
	if n == 1 {
		if err := s.client.Expire(ctx, key, window).Err(); err != nil {
			return 0, fmt.Errorf("counting sso redirects: %w", err)
		}
	}
	return n, nil
}
