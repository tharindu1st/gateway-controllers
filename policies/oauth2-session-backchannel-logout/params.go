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
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultClockSkew          = 60 * time.Second
	defaultMaxTokenAge        = 5 * time.Minute
	defaultJWKSCacheTTL       = 10 * time.Minute
	defaultJWKSRequestTimeout = 5 * time.Second

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "oauth2-session:v1:"
	defaultRedisConnectionTimeout = 5 * time.Second
	defaultRedisReadTimeout       = 3 * time.Second
	defaultRedisWriteTimeout      = 3 * time.Second
)

// supportedAlgorithms are the asymmetric JWS algorithms a logout token may be signed with.
// Symmetric (HS*) and "none" are never accepted.
var supportedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

var defaultAllowedAlgorithms = []string{"RS256"}

type config struct {
	issuer             string
	jwksURI            string
	clientID           string
	allowedAlgorithms  []string
	clockSkew          time.Duration
	maxTokenAge        time.Duration
	jwksCacheTTL       time.Duration
	jwksRequestTimeout time.Duration
	redis              redisParams
}

// redisParams must point at the same Redis, database and key prefix as oauth2-session.
type redisParams struct {
	host              string
	port              int
	username          string
	password          string
	db                int
	keyPrefix         string
	connectionTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	poolSize          int
}

func parseConfig(params map[string]interface{}) (*config, error) {
	c := &config{}
	var err error
	if c.issuer, err = requiredString(params, "issuer"); err != nil {
		return nil, err
	}
	if c.clientID, err = requiredString(params, "clientId"); err != nil {
		return nil, err
	}
	if c.jwksURI, err = requiredString(params, "jwksUri"); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.jwksURI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("'jwksUri' must be an absolute http or https URL without credentials")
	}

	c.allowedAlgorithms = getNestedStringListParam(params, "allowedAlgorithms")
	if len(c.allowedAlgorithms) == 0 {
		c.allowedAlgorithms = defaultAllowedAlgorithms
	}
	for _, alg := range c.allowedAlgorithms {
		if !supportedAlgorithms[alg] {
			return nil, fmt.Errorf("'allowedAlgorithms' contains unsupported algorithm %q", alg)
		}
	}

	c.clockSkew = getNestedDurationParam(params, "clockSkew", defaultClockSkew)
	if c.clockSkew < 0 {
		c.clockSkew = defaultClockSkew
	}
	c.maxTokenAge = getNestedPositiveDurationParam(params, "maxTokenAge", defaultMaxTokenAge)
	c.jwksCacheTTL = getNestedPositiveDurationParam(params, "jwksCacheTTL", defaultJWKSCacheTTL)
	c.jwksRequestTimeout = getNestedPositiveDurationParam(params, "jwksRequestTimeout", defaultJWKSRequestTimeout)

	c.redis = redisParams{
		host:              getNestedStringParam(params, "redis.host", defaultRedisHost),
		port:              getNestedIntParam(params, "redis.port", defaultRedisPort),
		username:          getNestedStringParam(params, "redis.username", ""),
		password:          getNestedStringParam(params, "redis.password", ""),
		db:                getNestedIntParam(params, "redis.db", 0),
		keyPrefix:         getNestedStringParam(params, "redis.keyPrefix", defaultRedisKeyPrefix),
		connectionTimeout: getNestedPositiveDurationParam(params, "redis.connectionTimeout", defaultRedisConnectionTimeout),
		readTimeout:       getNestedPositiveDurationParam(params, "redis.readTimeout", defaultRedisReadTimeout),
		writeTimeout:      getNestedPositiveDurationParam(params, "redis.writeTimeout", defaultRedisWriteTimeout),
		poolSize:          getNestedIntParam(params, "redis.poolSize", 0),
	}
	return c, nil
}

func requiredString(params map[string]interface{}, key string) (string, error) {
	v, ok := getNestedParam(params, key)
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return s, nil
}

// getNestedParam resolves a dotted key ("redis.host") against params, tolerating
// either nested maps or a flattened key.
func getNestedParam(params map[string]interface{}, dottedKey string) (interface{}, bool) {
	if v, ok := params[dottedKey]; ok {
		return v, true
	}
	var cur interface{} = params
	for _, part := range strings.Split(dottedKey, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func getNestedStringParam(params map[string]interface{}, dottedKey, def string) string {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return def
}

func getNestedIntParam(params map[string]interface{}, dottedKey string, def int) int {
	if v, ok := getNestedParam(params, dottedKey); ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func getNestedDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
				return d
			}
		}
	}
	return def
}

// getNestedPositiveDurationParam falls back to def when the parsed duration is <= 0.
func getNestedPositiveDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	d := getNestedDurationParam(params, dottedKey, def)
	if d <= 0 {
		return def
	}
	return d
}

// getNestedStringListParam returns the non-empty strings of a list parameter.
func getNestedStringListParam(params map[string]interface{}, dottedKey string) []string {
	v, ok := getNestedParam(params, dottedKey)
	if !ok {
		return nil
	}
	var out []string
	switch list := v.(type) {
	case []interface{}:
		for _, item := range list {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range list {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}
