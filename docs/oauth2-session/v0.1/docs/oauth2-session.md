---
title: "Overview"
---
# OAuth2 Session

## Overview

The **OAuth2 Session** policy logs browser users in with the OAuth 2.0
authorization code grant (RFC 6749 §4.1) and keeps their tokens on the
gateway. The gateway acts as a confidential OAuth client: the browser only
ever holds an opaque, signed session cookie, while the access token, refresh
token, expiry and scopes are stored encrypted in Redis. On every API call the
policy looks up the session, refreshes the access token shortly before it
expires, and sends it to the backend as a bearer token.

Attach the policy once at API level (`policies:`) and declare its login,
callback and logout paths as `GET` operations. The policy answers those three
routes itself; every other operation of the API requires a valid session.

## Features

- Authorization code grant with a confidential client
  (`client_secret_basic` or `client_secret_post`)
- Tokens never reach the browser: the cookie holds only a random 256-bit
  session ID signed with HMAC-SHA3-256
- Tokens encrypted at rest in Redis with AES-256-GCM; Redis keys are
  SHA3-256 hashes of the session ID, so a Redis dump contains nothing that
  works as a cookie
- Automatic refresh before expiry (`refreshBuffer`), with a per-session Redis
  lock so concurrent requests and replicas refresh only once, including with
  rotating refresh tokens
- Idle timeout (`idleTimeout`) and absolute session lifetime
  (`absoluteSessionTimeout`)
- Optional deep-link return after login (`/login?returnTo=/path`),
  restricted to same-site relative paths
- Single-use login state, bound to the browser by a short-lived state cookie
- Logout that deletes the session and can also redirect to the identity
  provider's logout endpoint
- The session cookies are removed from the request forwarded to the backend
- Fails closed when Redis is unavailable

## Configuration

This policy has two levels of configuration: **user parameters**, set per API,
and **system parameters**, set by the gateway operator in `config.toml`.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `authorizationEndpoint` | string | Yes | - | Identity provider authorization endpoint the browser is redirected to at login. Absolute `http`/`https` URL. Query parameters already on the URL are kept. |
| `tokenEndpoint` | string | Yes | - | Identity provider token endpoint used to redeem the authorization code and refresh tokens. |
| `clientId` | string | Yes | - | OAuth client ID registered for the gateway. |
| `clientSecret` | string | Yes | - | Client secret paired with `clientId`. Supply it as a secret reference, e.g. `'{{ secret "handle" }}'`. |
| `redirectUri` | string | Yes | - | Absolute callback URL registered at the identity provider, e.g. `https://gw.example.com/orders/v1/callback`. Its path must end with `callbackPath`; this is checked at deploy time. |
| `sessionSigningKey` | string | Yes | - | Secret used to sign session cookies, at least 32 bytes. Supply it as a secret reference. Changing it ends every session. |
| `tokenEncryptionKey` | string | Yes | - | Secret used to encrypt tokens in Redis, at least 32 bytes. Supply it as a secret reference. Changing it ends every session. |
| `clientAuthMethod` | string | No | `"client_secret_basic"` | How client credentials are sent to the token endpoint: `"client_secret_basic"` (HTTP Basic header) or `"client_secret_post"` (form fields). |
| `scopes` | string array | No | `[]` | Scopes requested at login, sent space-separated. |
| `loginPath` | string | No | `"/login"` | Operation path that starts a login. Must match a declared `GET` operation exactly, without the API context. |
| `callbackPath` | string | No | `"/callback"` | Operation path the identity provider redirects back to. Must match a declared `GET` operation. |
| `logoutPath` | string | No | `"/logout"` | Operation path that ends the session. Must match a declared `GET` operation. |
| `postLoginRedirect` | string | No | `"/"` | Path from the host root where users land after login when no valid `returnTo` is given. Include the API context, e.g. `/orders/v1/`. |
| `postLogoutRedirect` | string | No | `"/"` | Path from the host root where users land after logout. |
| `idleTimeout` | string | No | `"30m"` | A session not used for this long ends (Go duration format). Every authenticated request extends it. |
| `absoluteSessionTimeout` | string | No | `"8h"` | Maximum age of a session regardless of activity (Go duration format). The session cookie lives this long. |
| `cookie.name` | string | No | `"X-ABC"` | Session cookie name. A `__Host-` prefixed name (e.g. `__Host-X-ABC`) is recommended: browsers then refuse a cookie of that name set by another subdomain. |
| `cookie.stateCookieName` | string | No | `"X-ABC-state"` | Short-lived cookie that ties a login to the browser that started it. |
| `cookie.sameSite` | string | No | `"Lax"` | `SameSite` attribute of the session cookie: `"Lax"` or `"Strict"`. With `"Strict"`, the first page load after returning from the identity provider is sent without the cookie. The state cookie is always `Lax`. |
| `cookie.secure` | boolean | No | `true` | `Secure` attribute of both cookies. Disable only for local testing over plain HTTP; not allowed with `__Host-`/`__Secure-` names. |
| `authorizationRequestParams` | object (string map) | No | - | Extra authorization request parameters, e.g. `prompt` or `audience`. `response_type`, `client_id`, `redirect_uri`, `scope` and `state` are set by the policy and are rejected here. |
| `issuer` | string | No | `""` | Identity provider issuer identifier. When set, each new session is indexed by the `id_token`'s `sid` and `sub` so [OAuth2 Session Back-Channel Logout](../../../oauth2-session-backchannel-logout/v0.1/docs/oauth2-session-backchannel-logout.md) can end it, and an `id_token` whose `iss` or `aud` doesn't match fails the login. Requires the `openid` scope. |
| `endSessionEndpoint` | string | No | `""` | Identity provider logout URL (OpenID Connect RP-Initiated Logout). When set, logout redirects there with `client_id`, `id_token_hint` and `post_logout_redirect_uri`. |
| `refreshBuffer` | string | No | `"5m"` | How long before expiry the access token is refreshed (Go duration format). `0` refreshes only once expired. |
| `stateTTL` | string | No | `"5m"` | How long a started login may take to reach the callback (Go duration format). |
| `defaultTokenTTL` | string | No | `"1h"` | Access token lifetime assumed when the token response omits `expires_in`. |
| `upstreamHeaderName` | string | No | `"Authorization"` | Header on the backend request that carries the access token. |
| `upstreamValuePrefix` | string | No | `"Bearer"` | Prefix placed before the access token, separated by a space. Set `""` for no prefix. |
| `tokenRequestTimeout` | string | No | `"10s"` | Timeout for one token endpoint call (Go duration format). |
| `tokenRequestMaxRetries` | integer | No | `2` | Retries after a `429` or `5xx` from the token endpoint, with exponential backoff and jitter. Network errors are not retried, because the identity provider may already have used the single-use code or rotated the refresh token. |
| `proxyURL` | string | No | `""` | Proxy for token endpoint calls. Defaults to the `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables. |
| `tlsCaCert` | string | No | `""` | PEM CA certificate content to trust for the token endpoint's TLS connection, supplied as a secret reference. Replaces the system CAs for this connection. |
| `tlsInsecureSkipVerify` | boolean | No | `false` | Disables TLS verification for the token endpoint. Local testing only. |

### System Parameters (From config.toml)

Redis connection settings are set by the gateway operator in the policy's own
`policy_configurations.oauth2_session_v0.redis` section. Redis is required:
sessions and pending logins live only there.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `host` | string | No | `"localhost"` | Redis server hostname or IP address. |
| `port` | integer | No | `6379` | Redis server port. |
| `username` | string | No | `""` | Redis ACL username (Redis 6+). |
| `password` | string | No | `""` | Redis authentication password. |
| `db` | integer | No | `0` | Redis database index (0-15). |
| `keyPrefix` | string | No | `"oauth2-session:v1:"` | Prefix for every key this policy writes. |
| `connectionTimeout` | string | No | `"5s"` | Redis connection timeout (Go duration format). |
| `readTimeout` | string | No | `"3s"` | Redis read timeout (Go duration format). |
| `writeTimeout` | string | No | `"3s"` | Redis write timeout (Go duration format). |
| `poolSize` | integer | No | `0` | Connection pool size (`0` = go-redis default, 10 × GOMAXPROCS). One pool is shared by every oauth2-session instance with identical connection settings. |

Redis 6.2 or later is required (`GETEX` and `GETDEL` are used). Unlike
`oauth2-generator`, there is no `failureMode`: if Redis can't be reached,
requests fail closed with `503`.

#### Sample System Configuration

```toml
[policy_configurations.oauth2_session_v0.redis]
host = "redis.example.com"
port = 6379
key_prefix = "my-gateway:oauth2-session:"
```

## API Setup

The policy decides which route a request is for from the operation path the
gateway router matched (for example `/callback`), compared exactly with
`loginPath`, `callbackPath` and `logoutPath`. It never matches on the raw
request URL. So:

- Declare `loginPath`, `callbackPath` and `logoutPath` as `GET` operations.
  Without them the router rejects the request before the policy runs.
- `loginPath`, `callbackPath` and `logoutPath` are operation paths, without
  the API context.
- `postLoginRedirect`, `postLogoutRedirect` and `returnTo` are paths from the
  host root, with the API context.
- Every other operation requires a session. Put public endpoints, such as a
  health check or static files, in a separate API without this policy.

## How It Works

### Login (`GET loginPath`)

1. The optional `returnTo` query parameter is accepted only if it is a
   relative path starting with a single `/`, with no scheme, host, backslash
   or control characters; otherwise `postLoginRedirect` is used.
2. If the request carries a valid session, the policy refreshes the access
   token if needed and responds `302` to `returnTo`, re-issuing the session
   cookie.
3. Otherwise it generates a random `state`, stores `state → returnTo` in
   Redis for `stateTTL`, sets the state cookie, and responds `302` to
   `authorizationEndpoint` with `response_type=code`, `client_id`,
   `redirect_uri`, `scope` and `state`.

### Callback (`GET callbackPath`)

1. The `state` query parameter must equal the state cookie and match a
   pending login in Redis. The Redis record is deleted as it is read, so each
   `state` completes at most one login.
2. If the identity provider returned `error`, or no `code`, the login fails.
3. The code is redeemed at `tokenEndpoint` with `grant_type=authorization_code`
   and `redirect_uri`.
4. A brand-new session ID is generated (an ID the browser already had is
   never reused), the tokens are stored encrypted in Redis, and any previous
   session of this browser is deleted. When `issuer` is set, the session is
   also added to back-channel logout index sets keyed by the `id_token`'s
   `sid` and `sub`, in the same Redis transaction.
5. The policy responds `302` to `returnTo` with the session cookie.

### Every other operation

1. The session cookie is read; exactly one cookie of that name must be
   present. Its signature is checked before Redis is contacted, so forged
   cookies cost no Redis lookup.
2. The session is loaded from Redis and its idle timeout extended in the same
   call. Sessions older than `absoluteSessionTimeout` are deleted.
3. If the access token expires within `refreshBuffer`, it is refreshed (see
   below).
4. The access token is set in `upstreamHeaderName`, the session and state
   cookies are removed from the `Cookie` header sent to the backend, and the
   request is forwarded. The shared `AuthContext` records `AuthType`
   `oauth2-session`, the client ID and the granted scopes for later policies.
5. If the token was refreshed, the session cookie is re-issued on the
   backend's response with `Set-Cookie`.

### Refresh

- Only one request per session refreshes at a time, using a Redis lock.
  Other requests keep using the current token while it is still valid, or
  wait for the refresh to finish if it has expired.
- If the identity provider doesn't return a new refresh token, the old one
  is kept.
- If the identity provider rejects the refresh token (a `4xx` such as
  `invalid_grant`), the session ends and the request gets `401`.
- If the identity provider is temporarily unavailable, the current token is
  used while it is still valid. Once it has expired, requests get `503` and
  the session is kept so a later request can retry.
- A refresh only overwrites a session that still exists, so a session ended
  while its refresh was in flight (for example by back-channel logout) is
  never recreated.

### Logout initiated by the identity provider

When the user logs out at the identity provider, or the provider ends their
session, the gateway session is not ended by this policy alone. Two options:

- **Back-channel logout (recommended):** set `issuer` here and deploy
  [OAuth2 Session Back-Channel Logout](../../../oauth2-session-backchannel-logout/v0.1/docs/oauth2-session-backchannel-logout.md)
  on its own API. The identity provider then tells the gateway directly, and
  the sessions end immediately.
- **Without it:** the session ends at its idle or absolute timeout, or at the
  next refresh if the identity provider revoked the refresh token. Until then
  the current access token keeps being sent to the backend.

### Logout (`GET logoutPath`)

The session is deleted from Redis and the cookie cleared. The browser is
redirected to `postLogoutRedirect`, or to `endSessionEndpoint` when
configured. If Redis can't be reached, the response is `503` (the cookie is
still cleared), so a failed logout is never reported as a success.

## Reference Scenarios

### Example 1: Browser App With Deep-Link Return

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-web
spec:
  displayName: orders-web
  version: v1
  context: /orders/$version
  upstream:
    main:
      url: http://orders-backend:8080
  policies:
    - name: oauth2-session
      version: v0
      params:
        authorizationEndpoint: https://idp.example.com/oauth2/authorize
        tokenEndpoint: https://idp.example.com/oauth2/token
        clientId: orders-web
        clientSecret: '{{ secret "orders-web-client-secret" }}'
        redirectUri: https://gw.example.com/orders/v1/callback
        scopes: [openid, orders:read]
        postLoginRedirect: /orders/v1/
        postLogoutRedirect: /orders/v1/
        sessionSigningKey: '{{ secret "orders-web-session-key" }}'
        tokenEncryptionKey: '{{ secret "orders-web-token-key" }}'
        cookie:
          name: __Host-X-ABC
  operations:
    - method: GET
      path: /login
    - method: GET
      path: /callback
    - method: GET
      path: /logout
    - method: GET
      path: /orders
    - method: GET
      path: /orders/{id}
    - method: POST
      path: /orders
```

The app sends users to `/orders/v1/login?returnTo=/orders/v1/orders/42`;
after signing in they land back on `/orders/v1/orders/42`. API calls from the
app send the cookie automatically and reach the backend with
`Authorization: Bearer <access token>`.

### Example 2: Identity Provider Logout and Shorter Sessions

```yaml
  policies:
    - name: oauth2-session
      version: v0
      params:
        authorizationEndpoint: https://idp.example.com/oauth2/authorize
        tokenEndpoint: https://idp.example.com/oauth2/token
        endSessionEndpoint: https://idp.example.com/oidc/logout
        clientId: orders-web
        clientSecret: '{{ secret "orders-web-client-secret" }}'
        redirectUri: https://gw.example.com/orders/v1/callback
        scopes: [openid]
        sessionSigningKey: '{{ secret "orders-web-session-key" }}'
        tokenEncryptionKey: '{{ secret "orders-web-token-key" }}'
        idleTimeout: "15m"
        absoluteSessionTimeout: "4h"
        authorizationRequestParams:
          prompt: login
```

## Error Responses

All error responses are JSON (`Content-Type: application/json`) and carry
`Cache-Control: no-store`.

| Scenario | Status | Body `error` |
|----------|--------|--------------|
| No session cookie, forged or duplicate cookie, unknown, idle or expired session | 401 | `unauthorized` |
| Refresh token rejected by the identity provider | 401 | `unauthorized` |
| Callback with missing, mismatched, expired or reused `state` | 401 | `unauthorized` |
| Callback with an identity provider `error`, no `code`, or a rejected code | 401 | `unauthorized` |
| Redis unavailable | 503 | `service_unavailable` |
| Identity provider unavailable and the access token has expired, or the code exchange failed transiently | 503 | `service_unavailable` |
| Login, callback or logout called with a method other than `GET` | 405 | `method_not_allowed` |

**Example error body:**
```json
{
  "error": "unauthorized",
  "message": "Invalid or expired credentials."
}
```

Every authentication failure returns this identical `401`, whatever the
cause. The specific reason is logged internally only; session IDs and tokens
are never logged.

## Security Considerations

- **Use a `__Host-` cookie name** – it requires `Secure` and `Path=/` and
  stops a sibling subdomain from planting a session cookie. Requests that
  carry two cookies of the same name are rejected either way.
- **Treat `sessionSigningKey` and `tokenEncryptionKey` as credentials** –
  supply both as secret references. Rotating either ends every active
  session.
- **Access-control Redis** – records are encrypted and keyed by hash, but
  Redis still holds every active session and should be protected like any
  credential store.
- **The `id_token`'s signature is not checked** – it is received directly
  from the token endpoint over TLS (OpenID Connect Core §3.1.3.7), and is
  used only as `id_token_hint` at logout and, with `issuer` set, to index the
  session for back-channel logout after its `iss` and `aud` are checked. Do
  not rely on it for access decisions. Use an `https` `tokenEndpoint`.
- **Logout is a `GET`** – another site can link a user to the logout route
  and end their session. This can't expose data, but plan for it.
- **The state cookie isn't cleared after the callback** – a gateway-generated
  response can set only one cookie, so the state cookie simply expires after
  `stateTTL`. Its Redis record is already deleted, so it can't be reused.
- **`cookie.secure: false` and `tlsInsecureSkipVerify`** – for local testing
  only.

## Gateway Module Reference

```yaml
- name: oauth2-session
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-session@v0
```
