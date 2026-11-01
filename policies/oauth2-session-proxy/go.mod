module github.com/wso2/gateway-controllers/policies/oauth2-session-proxy

go 1.26.5

require (
	github.com/wso2/api-platform/sdk/core v0.5.0
	github.com/wso2/gateway-controllers/policies/oauth2-session v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

// The proxy is released together with oauth2-session, whose code it runs.
replace github.com/wso2/gateway-controllers/policies/oauth2-session => ../oauth2-session
