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
	"strings"
	"testing"
	"time"
)

func TestParseConfig_Defaults(t *testing.T) {
	c, err := parseConfig(validParams())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.audience != testIssuer || c.actorTokenType != DefaultActorTokenType || strings.Join(c.scopes, " ") != "openid" ||
		c.loginPath != "/login" || c.postLoginRedirect != "/" || c.transparentSSO || c.clientAuthMethod != ClientAuthMethodBasic {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.target.idleTimeout != 30*time.Minute || c.target.absoluteSessionTimeout != 8*time.Hour ||
		c.source.absoluteSessionTimeout != 8*time.Hour || c.target.cookieSameSite != SameSiteLax || !c.target.cookieSecure {
		t.Fatalf("unexpected session defaults: source %+v target %+v", c.source, c.target)
	}
	if c.resource != "" {
		t.Fatalf("resource must default to empty, got %q", c.resource)
	}
	if c.redis.keyPrefix != "oauth2-session:v1:" {
		t.Fatalf("keyPrefix = %q", c.redis.keyPrefix)
	}
	if string(c.source.signingKey) == string(c.target.signingKey) || string(c.target.signingKey) == string(c.target.encryptionKey) {
		t.Fatal("derived keys must differ")
	}
}

func TestParseConfig_Errors(t *testing.T) {
	set := func(path string, v interface{}) map[string]interface{} {
		p := validParams()
		parts := strings.Split(path, ".")
		m := p
		for _, part := range parts[:len(parts)-1] {
			m = m[part].(map[string]interface{})
		}
		if v == nil {
			delete(m, parts[len(parts)-1])
		} else {
			m[parts[len(parts)-1]] = v
		}
		return p
	}
	cases := map[string]struct {
		params map[string]interface{}
		want   string
	}{
		"missing endpoint":       {set("tokenEndpoint", nil), "'tokenEndpoint' parameter is required"},
		"http endpoint":          {set("tokenEndpoint", "http://idp.example.com/token"), "must be an absolute https URL"},
		"endpoint credentials":   {set("tokenEndpoint", "https://u:p@idp.example.com/token"), "must not contain credentials"},
		"missing client":         {set("clientId", nil), "'clientId' parameter is required"},
		"missing secret":         {set("clientSecret", nil), "'clientSecret' parameter is required"},
		"bad auth method":        {set("clientAuthMethod", "private_key_jwt"), "'clientAuthMethod' must be one of"},
		"no audience":            {set("issuer", nil), "'audience' is required"},
		"relative resource":      {set("resource", "/api"), "'resource' must be an absolute URI"},
		"resource fragment":      {set("resource", "https://api.example.com/#x"), "'resource' must be an absolute URI"},
		"relative login path":    {set("loginPath", "login"), "'loginPath' must start with '/'"},
		"unsafe post login":      {set("postLoginRedirect", "//evil.example.com"), "'postLoginRedirect' must be a relative path"},
		"missing source cookie":  {set("source.cookieName", nil), "'source.cookieName' parameter is required"},
		"bad target cookie":      {set("target.cookieName", "a b"), "'target.cookieName' is not a valid cookie name"},
		"same cookie":            {set("target.cookieName", sourceCookie), "must be different"},
		"short source secret":    {set("source.sessionSigningKey", "short"), "'source.sessionSigningKey' must be at least 32 bytes"},
		"missing target enc key": {set("target.tokenEncryptionKey", nil), "'target.tokenEncryptionKey' parameter is required"},
		"bad same site":          {set("target.sameSite", "None"), "'target.sameSite' must be one of"},
		"host cookie insecure":   {set("target.secure", false), "require 'target.secure' to be true"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			for _, secret := range []string{sourceSigning, sourceEncryption, targetSigning, targetEncryption, "billing-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("error message echoes a secret")
				}
			}
		})
	}
}

func TestParseConfig_InsecureEndpointOptIn(t *testing.T) {
	p := validParams()
	p["tokenEndpoint"] = "http://idp.local:8080/token"
	p["allowInsecureTokenEndpoint"] = true
	if _, err := parseConfig(p); err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
}

func TestParseConfig_AudienceWithoutIssuer(t *testing.T) {
	p := validParams()
	delete(p, "issuer")
	p["audience"] = "https://idp.example.com"
	c, err := parseConfig(p)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.issuer != "" || c.audience != "https://idp.example.com" {
		t.Fatalf("issuer %q audience %q", c.issuer, c.audience)
	}
}

func TestParseConfig_ExchangeLayout(t *testing.T) {
	const jwt = "urn:ietf:params:oauth:token-type:jwt"
	with := func(kv ...interface{}) map[string]interface{} {
		p := validParams()
		for i := 0; i < len(kv); i += 2 {
			p[kv[i].(string)] = kv[i+1]
		}
		return p
	}
	type layout struct{ subject, subjectType, actor, actorType string }
	cases := map[string]struct {
		params map[string]interface{}
		want   layout
	}{
		"Native SSO 1.0 default": {validParams(), layout{"id_token", TokenTypeIDToken, "device_secret", DefaultActorTokenType}},
		"legacy actorTokenType":  {with("actorTokenType", jwt), layout{"id_token", TokenTypeIDToken, "device_secret", jwt}},
		"device_secret subject swaps the pair": {with("subjectToken", "device_secret"),
			layout{"device_secret", DefaultActorTokenType, "id_token", TokenTypeIDToken}},
		"device_secret subject as jwt, no actor": {with("subjectToken", "device_secret", "subjectTokenType", jwt, "actorToken", "none"),
			layout{"device_secret", jwt, "none", ""}},
		"custom types": {with("subjectTokenType", "urn:example:id", "actorTokenType", "https://idp.example.com/ds"),
			layout{"id_token", "urn:example:id", "device_secret", "https://idp.example.com/ds"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := parseConfig(tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if got := (layout{c.subjectToken, c.subjectTokenType, c.actorToken, c.actorTokenType}); got != tc.want {
				t.Fatalf("layout = %+v, want %+v", got, tc.want)
			}
		})
	}

	errs := map[string]struct {
		params map[string]interface{}
		want   string
	}{
		"unknown subject":          {with("subjectToken", "access_token"), "'subjectToken' must be one of"},
		"unknown actor":            {with("actorToken", "refresh_token"), "'actorToken' must be one of"},
		"same subject and actor":   {with("actorToken", "id_token"), "must be different"},
		"no device_secret":         {with("actorToken", "none"), "must be \"device_secret\""},
		"subject can't be none":    {with("subjectToken", "none"), "'subjectToken' must be one of"},
		"relative subject type":    {with("subjectTokenType", "id_token"), "'subjectTokenType' must be an absolute URI"},
		"actor type with spaces":   {with("actorTokenType", "urn:a b"), "'actorTokenType' must be an absolute URI"},
		"actor type without actor": {with("subjectToken", "device_secret", "actorToken", "none", "actorTokenType", jwt), "must not be set"},
	}
	for name, tc := range errs {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
