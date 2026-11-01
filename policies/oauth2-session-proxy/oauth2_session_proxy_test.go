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

package oauth2sessionproxy

import (
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The behaviour is tested in the oauth2-session module; this checks the wiring.
func TestGetPolicy(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint":      "https://idp.example.com/oauth2/token",
		"clientId":           "orders-web",
		"clientSecret":       "client-secret",
		"sessionSigningKey":  strings.Repeat("s", 32),
		"tokenEncryptionKey": strings.Repeat("e", 32),
	}
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "test"}, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(policy.RequestHeaderPolicy); !ok {
		t.Fatalf("%T does not process request headers", p)
	}
	if _, ok := p.(policy.ResponseHeaderPolicy); !ok {
		t.Fatalf("%T does not process response headers", p)
	}
	if p.Mode().ResponseHeaderMode != policy.HeaderModeProcess {
		t.Fatal("response headers must be processed")
	}

	delete(params, "tokenEndpoint")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected an error without tokenEndpoint")
	}
}
