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
	"crypto/sha3"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// keyedSingleton is a process-wide, get-or-create registry of shared values,
// used here and by token_client.go's transport registry. build always
// runs outside the lock, so a slow build never stalls other keys.
type keyedSingleton[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]V
}

func newKeyedSingleton[K comparable, V any]() *keyedSingleton[K, V] {
	return &keyedSingleton[K, V]{m: make(map[K]V)}
}

// getOrCreate returns the cached value for key, building it on a miss.
// created is false on a hit or a lost build race. A failed build isn't cached.
func (r *keyedSingleton[K, V]) getOrCreate(key K, build func() (V, error)) (value V, created bool, err error) {
	r.mu.Lock()
	if v, ok := r.m[key]; ok {
		r.mu.Unlock()
		return v, false, nil
	}
	r.mu.Unlock()

	v, err := build()
	if err != nil {
		var zero V
		return zero, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.m[key]; ok {
		return existing, false, nil
	}
	r.m[key] = v
	return v, true, nil
}

// redisConnKey identifies a distinct Redis connection configuration; policy
// instances with identical settings share one *redis.Client. Excludes
// TLSConfig/credentials-provider options - see getOrCreateRedisClient's bypass.
type redisConnKey struct {
	addr         string
	username     string
	passwordHash string // sha3-256 hex; keeps the secret out of the in-process map key
	db           int
	protocol     int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	poolSize     int
}

// redisClients is the process-wide registry of shared Redis clients, avoiding a
// new connection pool per policy instance/config reload.
var redisClients = newKeyedSingleton[redisConnKey, *redis.Client]()

func hashRedisPassword(p string) string {
	if p == "" {
		return ""
	}
	sum := sha3.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these connection
// settings, creating (and pinging once) it on first use. Clients are never closed -
// they live for the process lifetime. pingErr is only meaningful when created is true;
// a reused client (created == false) always returns a nil pingErr, not a real ping result.
func getOrCreateRedisClient(opts *redis.Options, pingTimeout time.Duration) (client *redis.Client, created bool, pingErr error) {
	// TLSConfig/credentials-provider hooks aren't comparable, so bypass the
	// registry rather than risk reusing a client built for a different config.
	if opts.TLSConfig != nil || opts.CredentialsProvider != nil || opts.CredentialsProviderContext != nil || opts.StreamingCredentialsProvider != nil {
		c := redis.NewClient(opts)
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		defer cancel()
		pingErr = c.Ping(ctx).Err()
		return c, true, pingErr
	}

	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashRedisPassword(opts.Password),
		db:           opts.DB,
		protocol:     opts.Protocol,
		dialTimeout:  opts.DialTimeout,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		poolSize:     opts.PoolSize,
	}

	// go-redis dials lazily, so only the call that inserted the client pings it;
	// a concurrent caller reusing it is treated as already healthy.
	client, created, _ = redisClients.getOrCreate(key, func() (*redis.Client, error) {
		return redis.NewClient(opts), nil
	})
	if created {
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		defer cancel()
		pingErr = client.Ping(ctx).Err()
	}
	return client, created, pingErr
}
