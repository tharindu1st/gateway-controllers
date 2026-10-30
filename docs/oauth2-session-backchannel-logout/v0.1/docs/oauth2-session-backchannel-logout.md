---
title: "Overview"
---
# OAuth2 Session Back-Channel Logout

## Overview

The **OAuth2 Session Back-Channel Logout** policy implements
[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
for sessions created by the [OAuth2 Session](../../../oauth2-session/v0.1/docs/oauth2-session.md)
policy. When a user logs out at the identity provider, or the provider ends
their session, the provider sends a signed logout token directly to the
gateway. This policy validates it and deletes the matching gateway sessions
from Redis, so the user's session cookie stops working immediately.

The policy answers every request itself; nothing is forwarded to the
backend.

## Features

- Validates logout tokens as the specification requires: signature from the
  identity provider's JWKS with an allowed asymmetric algorithm, `iss`,
  `aud`, a recent `iat`, the back-channel logout event, a `jti`, a `sid` or
  `sub`, and no `nonce`
- Ends exactly the gateway sessions of one identity provider session
  (`sid`), or every gateway session of the user (`sub`) when the token has
  no `sid`
- Each logout token is accepted once (replay protection by `jti`)
- Signing keys are cached and refetched when the identity provider rotates
  them, with a rate limit on refetches for unknown key IDs
- Shares Redis settings with OAuth2 Session by default

## Prerequisites

- **OAuth2 Session with `issuer` set.** At login, OAuth2 Session then
  indexes each session by the `id_token`'s `sid` and `sub`. Sessions created
  before `issuer` was set can't be found by this policy.
- **The `openid` scope**, so the identity provider returns an `id_token`.
- **The same Redis, database and key prefix** as OAuth2 Session. Both
  policies read `policy_configurations.oauth2_session_v0.redis` by default.
- **The identity provider must reach the gateway** at the back-channel
  logout URL, and the client must be registered with that URL as its
  `backchannel_logout_uri`. Enable `backchannel_logout_session_required` if
  the provider supports it, so tokens carry `sid`.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuer` | string | Yes | - | Identity provider issuer identifier. Must equal the logout token's `iss` and OAuth2 Session's `issuer` exactly. |
| `jwksUri` | string | Yes | - | URL of the identity provider's JSON Web Key Set. Redirects are not followed. |
| `clientId` | string | Yes | - | Client ID used by OAuth2 Session. The logout token's `aud` must include it. |
| `allowedAlgorithms` | string array | No | `["RS256"]` | Accepted signing algorithms: any of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. Symmetric algorithms and `none` are never accepted. |
| `clockSkew` | string | No | `"60s"` | Allowed clock difference with the identity provider (Go duration format). |
| `maxTokenAge` | string | No | `"5m"` | Oldest logout token accepted, measured from its `iat` (Go duration format). |
| `jwksCacheTTL` | string | No | `"10m"` | How long fetched keys are reused before the JWKS is fetched again. A token naming an unknown key ID also triggers a fetch, at most once every 10 seconds. |
| `jwksRequestTimeout` | string | No | `"5s"` | Timeout for one JWKS request. |

### System Parameters (From config.toml)

Redis settings resolve from OAuth2 Session's section,
`policy_configurations.oauth2_session_v0.redis`, so a gateway configured for
OAuth2 Session needs nothing more. The parameters are the same as OAuth2
Session's (`host`, `port`, `username`, `password`, `db`, `keyPrefix`,
`connectionTimeout`, `readTimeout`, `writeTimeout`, `poolSize`); `keyPrefix`
in particular must match.

## API Setup

Deploy this policy on **its own API** with a single `POST` operation, and no
OAuth2 Session policy. OAuth2 Session protects every operation of the API it
is attached to, so on the same API it would reject the identity provider's
request (which carries no session cookie) before this policy runs. This
policy buffers the request body, which is another reason to keep it off the
API's other operations.

The upstream is required by the API definition but is never called.

## How It Works

1. The identity provider sends `POST` with
   `Content-Type: application/x-www-form-urlencoded` and a single
   `logout_token` parameter.
2. The token is validated (see [Features](#features)). The signing key is
   looked up by the token's `kid` in the cached JWKS, and the key type must
   match the algorithm, so an RSA key can't verify an `ES256` token or the
   reverse.
3. The token's `jti` is recorded in Redis for `maxTokenAge` plus twice
   `clockSkew`; a token whose `jti` was already seen is rejected. Without
   this, a captured `sub` token could be replayed to end sessions the user
   started after the original logout.
4. If the token has a `sid`, the gateway sessions of that identity provider
   session are deleted. Otherwise every gateway session of the `sub` is
   deleted. Sessions and their index set are deleted in one atomic Redis
   script.
5. The policy responds `200` with an empty body. If the deletion fails, the
   `jti` record is removed so the identity provider can retry the same
   token.

## Reference Scenarios

### Example: Back-Channel Logout API Next to an OAuth2 Session API

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-web-backchannel
spec:
  displayName: orders-web-backchannel
  version: v1
  context: /orders-auth/$version
  upstream:
    main:
      url: http://unused.invalid
  policies:
    - name: oauth2-session-backchannel-logout
      version: v0
      params:
        issuer: https://idp.example.com
        jwksUri: https://idp.example.com/oauth2/jwks
        clientId: orders-web
  operations:
    - method: POST
      path: /backchannel-logout
```

Register `https://gw.example.com/orders-auth/v1/backchannel-logout` as the
client's back-channel logout URL at the identity provider, and set
`issuer: https://idp.example.com` on the `orders-web` API's OAuth2 Session
policy.

## Error Responses

The specification requires `400 Bad Request` both for an invalid request and
for a logout that failed. Every response carries `Cache-Control: no-store`.

| Scenario | Status | Body `error` |
|----------|--------|--------------|
| Logout succeeded, including when no session matched | 200 | (empty body) |
| Wrong content type, missing or repeated `logout_token`, body over 64 KiB | 400 | `invalid_request` |
| Logout token invalid for any reason, or already used | 400 | `invalid_request` |
| Redis unavailable | 400 | `temporarily_unavailable` |
| Method other than `POST` | 405 | `method_not_allowed` |

The specific reason a token was rejected is logged internally only.

## Security Considerations

- **Only the identity provider should reach this URL.** The token signature
  is what makes a request trustworthy, but restricting the route by network
  or allowlist reduces load from junk requests.
- **Keep `allowedAlgorithms` to what the identity provider actually uses.**
- **`jwksUri` and `issuer` come from configuration only**, never from the
  request.
- **Logout by `sub` ends all of the user's gateway sessions** on every
  device. Prefer identity providers that send `sid`.
- **Classical signatures.** Logout tokens are verified with RSA or ECDSA, the
  algorithms identity providers use today. These are not quantum-resistant;
  post-quantum signatures will be added once identity providers publish such
  keys.

## Gateway Module Reference

```yaml
- name: oauth2-session-backchannel-logout
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-session-backchannel-logout@v0
```
