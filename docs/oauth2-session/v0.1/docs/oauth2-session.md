---
title: "Overview"
---
# OAuth2 Session

## Overview

The **OAuth2 Session** policy logs browser users in with the OAuth 2.0
authorization code grant (RFC 6749 §4.1) and keeps their tokens on the
gateway. The gateway acts as a confidential OAuth client: the browser only
ever holds an opaque, signed session cookie, while the access token, refresh
token, expiry and scopes are stored encrypted in Redis.

It is one of two policies that work together:

- **OAuth2 Session** (this policy) goes on the login, callback, logout,
  session, check-session and refresh operations, and answers them itself.
- **[OAuth2 Session Proxy](../../../oauth2-session-proxy/v0.1/docs/oauth2-session-proxy.md)** goes on the backend operations, including
  wildcard proxy routes. It turns the session cookie into a bearer token on
  the request sent to the backend, refreshing the access token shortly
  before it expires.

Both read the same Redis records, so they take the same client, cookie and
key settings. Attached to any other operation, this policy answers `404`.

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
- Backend operations take [OAuth2 Session Proxy](../../../oauth2-session-proxy/v0.1/docs/oauth2-session-proxy.md), which sends the
  access token upstream as a bearer token and removes the session cookies
  from the backend request
- A checkSession endpoint for the ThunderID SDK backend mode
  (`checkSessionPath`) that doesn't extend the idle timeout
- A session endpoint for the ThunderID SDK backend mode (`userinfoPath`),
  with the user's claims from the cached `id_token`, without calling the
  identity provider
- Stores the OpenID Connect Native SSO `device_secret` when the identity
  provider returns one (request the `device_sso` scope), keeping it across
  refreshes, so [OAuth2 Native SSO](../../../oauth2-native-sso/v0.1/docs/oauth2-native-sso.md)
  can sign the user in to another API. It never leaves the gateway.
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
| `logoutPath` | string | No | `"/logout"` | Operation path that ends the session. `GET` answers with a `302`; `POST` (the ThunderID SDK backend-mode signOut) answers `200 {"redirectUrl": ...}`. Declare it as a `GET` and/or `POST` operation. |
| `checkSessionPath` | string | No | `"/checksession"` | Operation path of the checkSession endpoint for the ThunderID SDK backend mode. Same payload as `userinfoPath`, but doesn't extend the idle timeout or refresh. Declare it as a `GET` operation to use it. See [Check Session](#check-session-get-checksessionpath). |
| `userinfoPath` | string | No | `"/userinfo"` | Operation path of the session endpoint for the ThunderID SDK backend mode: `{"isSignedIn", "user", "expiresAt"}`, with the user claims from the cached `id_token`. Declare it as a `GET` operation to use it. See [User Info](#user-info-get-userinfopath). |
| `refreshPath` | string | No | `"/refresh"` | Operation path of the refresh endpoint for the ThunderID SDK backend mode: `POST` refreshes the access token and answers `204`. Declare it as a `POST` operation to use it. See [Refresh on Request](#refresh-on-request-post-refreshpath). |
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
| `refreshCooldown` | string | No | `"30s"` | `POST refreshPath` keeps an access token obtained less than this long ago instead of refreshing it, so repeated calls can't make each one a refresh (Go duration format). |
| `stateTTL` | string | No | `"5m"` | How long a started login may take to reach the callback (Go duration format). |
| `defaultTokenTTL` | string | No | `"1h"` | Access token lifetime assumed when the token response omits `expires_in`. |
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

Attach the policy to each of its operations, and
[OAuth2 Session Proxy](../../../oauth2-session-proxy/v0.1/docs/oauth2-session-proxy.md) to the backend operations. A YAML anchor keeps
the shared settings in one place; see
[Example 1](#example-1-browser-app-with-deep-link-return).

The policy decides which route a request is for from the operation path the
gateway router matched (for example `/callback`), compared exactly with
`loginPath`, `callbackPath`, `logoutPath`, `checkSessionPath`,
`userinfoPath` and `refreshPath`. It never matches on the raw request URL.
So:

- Declare `loginPath`, `callbackPath` and `logoutPath` as `GET` operations
  (`logoutPath` also or only as `POST`), and `checkSessionPath`,
  `userinfoPath` (`GET`) and `refreshPath` (`POST`) if the app uses them.
  Without them the router rejects the request before the policy runs.
- All six are operation paths, without the API context, and must be
  different from each other.
- `postLoginRedirect`, `postLogoutRedirect` and `returnTo` are paths from the
  host root, with the API context.
- On any other operation this policy answers `404` and logs a warning: it
  never forwards a request, because the request would reach the backend
  without a token.
- Give both policies the same `tokenEndpoint`, `clientId`, `clientSecret`,
  `clientAuthMethod`, `sessionSigningKey`, `tokenEncryptionKey`, `cookie`,
  `idleTimeout` and `absoluteSessionTimeout`. With different keys or cookie
  settings, OAuth2 Session Proxy can't read the sessions this policy creates,
  and every backend call gets `401`.
- Put public endpoints, such as a health check or static files, on
  operations without either policy, or in a separate API.

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

### Backend operations

[OAuth2 Session Proxy](../../../oauth2-session-proxy/v0.1/docs/oauth2-session-proxy.md) authenticates them from the session cookie and
sends the access token to the backend. It refreshes tokens as described
below, and reacts to a backend `401` by marking the token for refresh.

### Refresh

The same refresh logic runs in this policy (`GET loginPath`,
`GET userinfoPath`, `POST refreshPath`) and in OAuth2 Session Proxy, on the
same Redis records.


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

### Check Session (`GET checkSessionPath`)

The checkSession endpoint of the ThunderID SDK's backend mode, which the SDK
polls (`session.checkInterval`). It returns the same `200` payload as
[User Info](#user-info-get-userinfopath): `{"isSignedIn": true, "user":
{...}, "expiresAt": ...}` with a live session, otherwise
`{"isSignedIn": false}`.

With `{"isSignedIn": false}`, a session cookie the request carried is expired
in the same response (`Set-Cookie: <cookie.name>=; Max-Age=0`), since it no
longer leads to a session; a request without one gets no `Set-Cookie`. A
session that can no longer be used (past `absoluteSessionTimeout`, or an
expired access token with no refresh token) is also deleted from Redis.

The difference is that this route reads Redis only. It doesn't extend the
idle timeout, so a page that polls it doesn't keep an abandoned session
alive, and it never calls the identity provider. A session whose access
token has expired still reports `isSignedIn: true` while it has a refresh
token (its `expiresAt` is then in the past), since the next API call or
refresh renews it. If Redis can't be reached the response is `503` and the
cookie is kept, so an outage never signs the user out.

### User Info (`GET userinfoPath`)

Serves the session endpoint of the ThunderID SDK's backend mode, so the app
can show who is signed in without receiving any token. Both answers are
`200`:

```json
{
  "isSignedIn": true,
  "user": { "sub": "user-1", "name": "User One", "email": "user1@example.com" },
  "expiresAt": 1800003600
}
```

```json
{ "isSignedIn": false }
```

- `user` holds the claims of the `id_token` cached in the session; the
  identity provider is not called. Protocol claims such as `iss`, `aud`,
  `azp`, `exp`, `iat`, `nonce`, `at_hash`, `sid`, `auth_time`, `acr` and
  `amr` are removed.
- `expiresAt` is when the current access token expires (Unix seconds). It
  moves forward after each refresh.
- Without a session, for any reason (no cookie, forged cookie, logged out,
  expired, refresh token rejected), the answer is the same
  `{"isSignedIn": false}`, so it reveals nothing about why. A session cookie
  the request carried is expired in the same response.
- The `id_token` is the one received at login, replaced whenever a refresh
  response includes a new one. Claims the user changes at the identity
  provider appear after such a refresh or the next login. Request scopes
  such as `openid profile email`; without an `id_token` (no `openid` scope)
  `user` is empty.
- If Redis can't be reached the response is `503`, not `isSignedIn: false`.

Like an API call, this route extends the idle timeout and refreshes the
access token when it is about to expire; the cookie is re-issued after a
refresh.

### Refresh on Request (`POST refreshPath`)

The refresh endpoint of the ThunderID SDK's backend mode. `POST` refreshes
the access token now, using the refresh token held in Redis. Tokens are also
refreshed automatically, so apps don't need to call it.

- Success is `204` with no body; the session cookie is re-issued when new
  tokens were stored. Like an API call, it extends the idle timeout. The SDK
  then reads the session endpoint again, which shows the new `expiresAt`.
- Without a session, or when the identity provider rejects the refresh token
  (the session then ends), the answer is the standard `401`. The SDK checks
  only whether the response succeeded, and signs the user out otherwise.
- A token obtained less than `refreshCooldown` ago (default 30s) is kept, still answering `204`, so repeated calls can't flood the
  identity provider. Concurrent calls refresh once, using the refresh lock.
  A session without a refresh token is kept as is while its token is valid.
- If the identity provider is temporarily unavailable, the current token is
  kept while still valid (`204`); if Redis can't be reached the answer is
  `503`. Methods other than `POST` get `405`.

### Logout (`GET` or `POST logoutPath`)

Two forms, which end the session the same way:

- **`GET`**, a plain link such as `<a href="/orders/v1/logout">Sign out</a>`:
  the answer is a `302` to the logout destination.
- **`POST`**, the ThunderID SDK's backend-mode signOut: the answer is
  `200 {"redirectUrl": "<destination>"}`, and the SDK navigates there itself.

The destination is the identity provider's end-session URL when
`endSessionEndpoint` is set, otherwise `postLogoutRedirect`. Other methods get
`405`. Declare only the methods the app uses.

```
GET /orders/v1/logout   (Cookie: X-ABC=<session>)
 1. Verify the cookie signature. Missing or invalid: skip to step 4.
 2. One Redis transaction: read and delete the session (GETDEL) and delete
    its refresh lock.
 3. With `issuer` set, remove the session from the back-channel index sets
    (best effort; the sets also expire on their own).
 4. Destination: endSessionEndpoint?client_id=…&id_token_hint=…&post_logout_redirect_uri=…
    or, without endSessionEndpoint, postLogoutRedirect.
    GET: 302 to it.  POST: 200 {"redirectUrl": "<destination>"}.
    Set-Cookie clears the session cookie; Cache-Control: no-store.
```

- The `id_token_hint` comes from the record that was deleted, so the identity
  provider logout always matches the session that ended.
  `post_logout_redirect_uri` is the origin of `redirectUri` plus
  `postLogoutRedirect`; register that exact URL at the identity provider.
- Logging out without a session, with a forged cookie, or a second time gives
  the same destination (without `id_token_hint`), so the route is safe to
  call repeatedly.
- If Redis can't be reached, the response is `503` with the cookie still
  cleared, so a failed logout is never reported as a success.
- The refresh token is deleted from Redis but not revoked separately at the
  identity provider. With `endSessionEndpoint`, identity providers end their
  own session and normally invalidate its tokens; without it, the refresh
  token stays valid at the identity provider until it expires, and the
  gateway never uses it again.
- The state cookie isn't cleared by logout (a gateway response can set only
  one cookie); it expires after `stateTTL`.

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
  operations:
    # Answered by oauth2-session.
    - method: GET
      path: /login
      policies:
        - &session
          name: oauth2-session
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
    - {method: GET, path: /callback, policies: [*session]}
    - {method: GET, path: /logout, policies: [*session]}
    - {method: GET, path: /checksession, policies: [*session]}
    - {method: GET, path: /userinfo, policies: [*session]}

    # Backend operations: the session's access token is sent as a bearer token.
    - method: GET
      path: /orders
      policies:
        - &proxy
          name: oauth2-session-proxy
          version: v0
          params:
            tokenEndpoint: https://idp.example.com/oauth2/token
            clientId: orders-web
            clientSecret: '{{ secret "orders-web-client-secret" }}'
            sessionSigningKey: '{{ secret "orders-web-session-key" }}'
            tokenEncryptionKey: '{{ secret "orders-web-token-key" }}'
            cookie:
              name: __Host-X-ABC
    - {method: GET, path: '/orders/{id}', policies: [*proxy]}
    - {method: POST, path: /orders, policies: [*proxy]}
```

The app sends users to `/orders/v1/login?returnTo=/orders/v1/orders/42`;
after signing in they land back on `/orders/v1/orders/42`. API calls from the
app send the cookie automatically and reach the backend with
`Authorization: Bearer <access token>`. On page load the app calls
`/orders/v1/checksession` to decide whether to show the login button, and
`/orders/v1/userinfo` to show the user's name.

### Example 2: Identity Provider Logout and Shorter Sessions

The `params` of the oauth2-session attachment. Set the same `idleTimeout`
and `absoluteSessionTimeout` on the OAuth2 Session Proxy attachment.

```yaml
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
| No session cookie, forged or duplicate cookie, unknown, idle or expired session on `refreshPath` (on `userinfoPath` and `checkSessionPath`: `200 {"isSignedIn": false}` instead; `GET loginPath` starts a new login) | 401 | `unauthorized` |
| Refresh token rejected by the identity provider | 401 | `unauthorized` |
| Callback with missing, mismatched, expired or reused `state` | 401 | `unauthorized` |
| Callback with an identity provider `error`, no `code`, or a rejected code | 401 | `unauthorized` |
| The policy is attached to an operation that isn't one of its routes | 404 | `not_found` |
| Redis unavailable | 503 | `service_unavailable` |
| Identity provider unavailable and the access token has expired, or the code exchange failed transiently | 503 | `service_unavailable` |
| Login, callback, check-session or userinfo called with a method other than `GET`, logout with a method other than `GET` or `POST`, or refresh with a method other than `POST` | 405 | `method_not_allowed` |

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
  used only as `id_token_hint` at logout, as the source of `userinfoPath`
  claims, and, with `issuer` set, to index the session for back-channel
  logout after its `iss` and `aud` are checked. Do not rely on it for access
  decisions. Use an `https`
  `tokenEndpoint`.
- **Check-session and userinfo responses describe one user** – they carry
  `Cache-Control: no-store`. They are `GET` routes that read only the
  caller's own session, and a cross-site page can't read their responses
  unless a CORS policy on the API allows that origin with credentials.
- **Logout over `GET` can be triggered by another site** – a link or image
  elsewhere can end the user's session. This can't expose data. `POST`
  logout can't be triggered that way: browsers don't send the `SameSite`
  session cookie with a cross-site `POST`. Declare only `POST` if the app
  doesn't need link-based logout.
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
