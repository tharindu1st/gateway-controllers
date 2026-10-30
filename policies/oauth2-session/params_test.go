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
)

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"authorizationEndpoint": "https://idp.example.com/oauth2/authorize",
		"tokenEndpoint":         "https://idp.example.com/oauth2/token",
		"clientId":              "orders-web",
		"clientSecret":          "client-secret",
		"redirectUri":           "https://gw.example.com/orders/v1/callback",
		"sessionSigningKey":     strings.Repeat("s", 32),
		"tokenEncryptionKey":    strings.Repeat("e", 32),
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	c, err := parseConfig(validParams())
	if err != nil {
		t.Fatal(err)
	}
	if c.loginPath != "/login" || c.callbackPath != "/callback" || c.logoutPath != "/logout" {
		t.Errorf("unexpected default paths: %q %q %q", c.loginPath, c.callbackPath, c.logoutPath)
	}
	if c.cookieName != "X-ABC" || c.stateCookieName != "X-ABC-state" || c.cookieSameSite != SameSiteLax || !c.cookieSecure {
		t.Errorf("unexpected cookie defaults: %+v", c)
	}
	if c.idleTimeout != 30*time.Minute || c.absoluteSessionTimeout != 8*time.Hour || c.refreshBuffer != 5*time.Minute {
		t.Errorf("unexpected timing defaults")
	}
	if c.clientAuthMethod != ClientAuthMethodBasic || c.upstreamHeaderName != "Authorization" || c.upstreamValuePrefix != "Bearer" {
		t.Errorf("unexpected token defaults")
	}
	if len(c.signingKey) != 32 || len(c.encryptionKey) != 32 || string(c.signingKey) == string(c.encryptionKey) {
		t.Errorf("derived keys must be 32 bytes and distinct")
	}
	if c.redis.keyPrefix != "oauth2-session:v1:" || c.redis.port != 6379 {
		t.Errorf("unexpected redis defaults")
	}
}

func TestParseConfig_NestedAndExplicitValues(t *testing.T) {
	p := validParams()
	p["scopes"] = []interface{}{"openid", " orders:read ", ""}
	p["cookie"] = map[string]interface{}{"name": "__Host-X-ABC", "sameSite": "Strict"}
	p["upstreamValuePrefix"] = ""
	p["redis"] = map[string]interface{}{"host": "redis", "port": float64(6380)}
	c, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.scopes, ",") != "openid,orders:read" {
		t.Errorf("scopes = %v", c.scopes)
	}
	if c.cookieName != "__Host-X-ABC" || c.cookieSameSite != SameSiteStrict {
		t.Errorf("cookie = %q %q", c.cookieName, c.cookieSameSite)
	}
	if c.upstreamValuePrefix != "" {
		t.Errorf("explicit empty prefix must be honored")
	}
	if c.redis.host != "redis" || c.redis.port != 6380 {
		t.Errorf("redis = %s:%d", c.redis.host, c.redis.port)
	}
}

func TestParseConfig_Rejects(t *testing.T) {
	cases := map[string]func(p map[string]interface{}){
		"missing clientId":           func(p map[string]interface{}) { delete(p, "clientId") },
		"relative token endpoint":    func(p map[string]interface{}) { p["tokenEndpoint"] = "/token" },
		"ftp authorization endpoint": func(p map[string]interface{}) { p["authorizationEndpoint"] = "ftp://idp/authorize" },
		"credentials in endpoint":    func(p map[string]interface{}) { p["tokenEndpoint"] = "https://u:p@idp/token" },
		"short signing key":          func(p map[string]interface{}) { p["sessionSigningKey"] = "short" },
		"short encryption key":       func(p map[string]interface{}) { p["tokenEncryptionKey"] = "short" },
		"redirectUri path mismatch":  func(p map[string]interface{}) { p["callbackPath"] = "/cb" },
		"path without slash":         func(p map[string]interface{}) { p["loginPath"] = "login" },
		"duplicate paths":            func(p map[string]interface{}) { p["logoutPath"] = "/login" },
		"absolute postLoginRedirect": func(p map[string]interface{}) { p["postLoginRedirect"] = "https://evil.com" },
		"protocol-relative redirect": func(p map[string]interface{}) { p["postLogoutRedirect"] = "//evil.com" },
		"bad clientAuthMethod":       func(p map[string]interface{}) { p["clientAuthMethod"] = "private_key_jwt" },
		"bad sameSite":               func(p map[string]interface{}) { p["cookie"] = map[string]interface{}{"sameSite": "None"} },
		"bad cookie name":            func(p map[string]interface{}) { p["cookie"] = map[string]interface{}{"name": "a b"} },
		"same cookie names": func(p map[string]interface{}) {
			p["cookie"] = map[string]interface{}{"name": "X", "stateCookieName": "X"}
		},
		"__Host- without secure": func(p map[string]interface{}) {
			p["cookie"] = map[string]interface{}{"name": "__Host-X", "secure": false}
		},
		"reserved authorization param": func(p map[string]interface{}) {
			p["authorizationRequestParams"] = map[string]interface{}{"redirect_uri": "https://evil.com"}
		},
	}
	for name, mutate := range cases {
		p := validParams()
		mutate(p)
		if _, err := parseConfig(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseConfig_ErrorsNeverContainSecrets(t *testing.T) {
	p := validParams()
	p["sessionSigningKey"] = "super-secret-but-short"
	_, err := parseConfig(p)
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error must not echo the secret: %v", err)
	}
}
