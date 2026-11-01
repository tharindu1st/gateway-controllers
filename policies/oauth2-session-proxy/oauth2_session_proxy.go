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

// Package oauth2sessionproxy is the oauth2-session-proxy policy. Its behaviour lives in the
// oauth2-session module, next to the code that creates the sessions it reads, so the two always
// agree on the cookie, the keys and the Redis records.
package oauth2sessionproxy

import (
	"context"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	oauth2session "github.com/wso2/gateway-controllers/policies/oauth2-session"
)

// Policy is one oauth2-session-proxy attachment. The gateway builder looks for the policy
// methods in this module's source, so they are declared here and delegate to oauth2-session.
type Policy struct {
	proxy *oauth2session.ProxyPolicy
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	proxy, err := oauth2session.NewProxyPolicy(metadata, params)
	if err != nil {
		return nil, err
	}
	return &Policy{proxy: proxy}, nil
}

// Mode processes request and response headers; bodies are never buffered.
func (p *Policy) Mode() policy.ProcessingMode {
	return p.proxy.Mode()
}

// OnRequestHeaders authenticates the request from its session cookie and sets the bearer token.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	return p.proxy.OnRequestHeaders(ctx, reqCtx, params)
}

// OnResponseHeaders re-issues a refreshed session cookie and notices a backend 401.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	return p.proxy.OnResponseHeaders(ctx, respCtx, params)
}
