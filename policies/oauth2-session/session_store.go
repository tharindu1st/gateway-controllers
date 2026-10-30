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

// session is the server-side record behind one session cookie. It is stored encrypted.
type session struct {
	AccessToken  string   `json:"at"`
	RefreshToken string   `json:"rt,omitempty"`
	TokenType    string   `json:"tt,omitempty"`
	IDToken      string   `json:"it,omitempty"`
	Scopes       []string `json:"sc,omitempty"`
	ExpiresAt    int64    `json:"exp"` // access token expiry, unix seconds
	CreatedAt    int64    `json:"cat"` // login time, unix seconds; anchors absoluteSessionTimeout
}

func (s *session) expiry() time.Time  { return time.Unix(s.ExpiresAt, 0) }
func (s *session) created() time.Time { return time.Unix(s.CreatedAt, 0) }

// releaseLockScript deletes the lock only if it still holds this caller's token, so a refresh
// that outlived its lock TTL can't release a lock another replica has since taken.
var releaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0`)

// sessionStore keeps sessions, pending login states and refresh locks in Redis. Keys are built
// from a SHA3-256 hash of the session ID or state, so a Redis dump never contains a value that
// could be replayed as a cookie.
type sessionStore struct {
	client       *redis.Client
	prefix       string
	aead         cipher.AEAD
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func newSessionStore(client *redis.Client, rp redisParams, encryptionKey []byte) (*sessionStore, error) {
	block, err := aes.NewCipher(encryptionKey) // 32-byte key: AES-256
	if err != nil {
		return nil, fmt.Errorf("creating token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating token cipher: %w", err)
	}
	return &sessionStore{
		client:       client,
		prefix:       rp.keyPrefix,
		aead:         aead,
		readTimeout:  rp.readTimeout,
		writeTimeout: rp.writeTimeout,
	}, nil
}

func hashID(id string) string {
	sum := sha3.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func (s *sessionStore) sessionKey(sid string) string { return s.prefix + "sess:" + hashID(sid) }
func (s *sessionStore) stateKey(state string) string { return s.prefix + "state:" + hashID(state) }
func (s *sessionStore) lockKey(sid string) string    { return s.prefix + "lock:" + hashID(sid) }

// loadSession returns the session for sid and slides its Redis TTL to idleTimeout in the same
// round trip (GETEX). It returns (nil, nil) when there is no such session.
func (s *sessionStore) loadSession(ctx context.Context, sid string, idleTimeout time.Duration) (*session, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	key := s.sessionKey(sid)
	raw, err := s.client.GetEx(ctx, key, idleTimeout).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading session: %w", err)
	}
	return s.decryptSession(key, raw)
}

// getSession reads a session without touching its TTL; used to re-read after another replica's refresh.
func (s *sessionStore) getSession(ctx context.Context, sid string) (*session, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	key := s.sessionKey(sid)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading session: %w", err)
	}
	return s.decryptSession(key, raw)
}

// idpIndexKey is the key of the set that lists the gateway sessions belonging to one identity
// provider session (kind "sid") or user (kind "sub"). The oauth2-session-backchannel-logout
// policy builds the same keys, so this format must not change without changing it there too.
func (s *sessionStore) idpIndexKey(kind, issuer, value string) string {
	return s.prefix + "idp-" + kind + ":" + hashID(issuer+"\x00"+value)
}

// createSession stores a new session and, in the same MULTI/EXEC transaction, adds it to the
// given identity provider index sets. Each set's TTL is reset to indexTTL, which covers the
// lifetime of its newest member.
func (s *sessionStore) createSession(ctx context.Context, sid string, sess *session, ttl time.Duration,
	indexKeys []string, indexTTL time.Duration) error {
	key := s.sessionKey(sid)
	sealed, err := s.sealSession(key, sess)
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
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("writing session: %w", err)
	}
	return nil
}

// updateSession overwrites an existing session only (SET XX). ok is false when the session no
// longer exists - for example a back-channel logout removed it while a refresh was running -
// so a refresh can never bring an ended session back.
func (s *sessionStore) updateSession(ctx context.Context, sid string, sess *session, ttl time.Duration) (ok bool, err error) {
	key := s.sessionKey(sid)
	sealed, err := s.sealSession(key, sess)
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	ok, err = s.client.SetXX(ctx, key, sealed, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("writing session: %w", err)
	}
	return ok, nil
}

// sealSession encrypts a session record. The Redis key is the additional data, so a ciphertext
// copied under another key won't decrypt.
func (s *sessionStore) sealSession(key string, sess *session) ([]byte, error) {
	plain, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("encoding session: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(key)), nil
}

func (s *sessionStore) deleteSession(ctx context.Context, sid string) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	if err := s.client.Del(ctx, s.sessionKey(sid)).Err(); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

func (s *sessionStore) decryptSession(key string, raw []byte) (*session, error) {
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("session record is truncated")
	}
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(key))
	if err != nil {
		// Wrong key (e.g. tokenEncryptionKey rotated) or tampered record.
		return nil, fmt.Errorf("decrypting session: %w", err)
	}
	var sess session
	if err := json.Unmarshal(plain, &sess); err != nil {
		return nil, fmt.Errorf("decoding session: %w", err)
	}
	return &sess, nil
}

// saveState records a pending login: state -> returnTo, valid for ttl.
func (s *sessionStore) saveState(ctx context.Context, state, returnTo string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	if err := s.client.Set(ctx, s.stateKey(state), returnTo, ttl).Err(); err != nil {
		return fmt.Errorf("writing login state: %w", err)
	}
	return nil
}

// takeState reads and deletes a pending login in one step (GETDEL), so each state value can
// complete at most one login. found is false when the state is unknown, expired or already used.
func (s *sessionStore) takeState(ctx context.Context, state string) (returnTo string, found bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	returnTo, err = s.client.GetDel(ctx, s.stateKey(state)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading login state: %w", err)
	}
	return returnTo, true, nil
}

// acquireRefreshLock takes the per-session refresh lock (SET NX PX). It returns the lock token
// to pass to releaseRefreshLock, or ok=false when another request holds it.
func (s *sessionStore) acquireRefreshLock(ctx context.Context, sid string, ttl time.Duration) (token string, ok bool, err error) {
	token, err = newRandomID()
	if err != nil {
		return "", false, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	ok, err = s.client.SetNX(ctx, s.lockKey(sid), token, ttl).Result()
	if err != nil {
		return "", false, fmt.Errorf("acquiring refresh lock: %w", err)
	}
	return token, ok, nil
}

func (s *sessionStore) releaseRefreshLock(ctx context.Context, sid, token string) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()
	if err := releaseLockScript.Run(ctx, s.client, []string{s.lockKey(sid)}, token).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("releasing refresh lock: %w", err)
	}
	return nil
}

func (s *sessionStore) refreshLockHeld(ctx context.Context, sid string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	n, err := s.client.Exists(ctx, s.lockKey(sid)).Result()
	if err != nil {
		return false, fmt.Errorf("checking refresh lock: %w", err)
	}
	return n > 0, nil
}
