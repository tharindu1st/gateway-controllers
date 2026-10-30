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

import "testing"

// TestIdpIndexKeyFormat pins the Redis key format shared with oauth2-session-backchannel-logout;
// its TestIndexKeyFormat asserts the same literals. Change both together or back-channel logout
// stops finding sessions.
func TestIdpIndexKeyFormat(t *testing.T) {
	s := &sessionStore{prefix: "oauth2-session:v1:"}
	got := s.idpIndexKey("sid", "https://idp.example.com", "idp-session-1")
	want := "oauth2-session:v1:idp-sid:a8d87ebcd6fd2b62d66b060dfaf245b72775ae073c48fbd7fb60e38eb4a2c72c"
	if got != want {
		t.Fatalf("index key = %q, want %q", got, want)
	}
	if s.sessionKey("gateway-session-id") != "oauth2-session:v1:sess:882b20bf25845c594720ed7862e5d707d6a5ecfc753a22ac8e018231dfa26da4" {
		t.Fatalf("session key format changed: %q", s.sessionKey("gateway-session-id"))
	}
}
