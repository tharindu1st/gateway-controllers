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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// maxIDTokenBytes bounds the id_token this policy will decode.
const maxIDTokenBytes = 64 << 10

// idTokenClaims are the id_token claims needed to index a session for back-channel logout.
type idTokenClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Sid string          `json:"sid"`
	Aud json.RawMessage `json:"aud"`
}

// parseIDTokenClaims decodes the payload of an id_token WITHOUT verifying its signature. That
// is acceptable only because the token was received directly from the token endpoint over TLS
// (OpenID Connect Core §3.1.3.7, step 6), and the claims are used only to find this session
// again at back-channel logout - never to decide whether a request is allowed.
func parseIDTokenClaims(raw string) (*idTokenClaims, error) {
	if len(raw) > maxIDTokenBytes {
		return nil, fmt.Errorf("id_token is too large")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token is not a JWS compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("decoding id_token payload: %w", err)
	}
	var c idTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("decoding id_token claims: %w", err)
	}
	return &c, nil
}

// hasAudience reports whether aud, a string or an array of strings, contains clientID.
func (c *idTokenClaims) hasAudience(clientID string) bool {
	var single string
	if json.Unmarshal(c.Aud, &single) == nil {
		return single == clientID
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}
