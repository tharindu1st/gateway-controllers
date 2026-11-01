---
title: "Overview"
---
# OAuth2 Session Proxy

## Overview

The **OAuth2 Session Proxy** policy turns the browser session created by
[OAuth2 Session](../../../oauth2-session/v0.1/docs/oauth2-session.md) into a
bearer token on the request sent to the backend. The browser sends only its
opaque session cookie. The policy looks up the session in Redis, refreshes
the access token shortly before it expires, sets it in the `Authorization`
header, and removes the session cookies from the request forwarded upstream.

OAuth2 Session answers the login, callback, logout, session, check-session
and refresh operations. This policy goes on the operations that reach the
backend. It authenticates every request on the operations it is attached
to, whatever their path, so it suits wildcard proxy routes such as `/*`. It
never answers a login or logout route itself.

## Features

- Session cookie to `Authorization: Bearer <access token>` on the upstream
  request; the session and state cookies are removed from the backend's
  `Cookie` header
- Automatic refresh before expiry (`refreshBuffer`), with the same per-session
  Redis lock as OAuth2 Session, so concurrent requests, replicas and both
  policies refresh only once, including with rotating refresh tokens
- Early refresh when the backend rejects the access token with `401`
  (`refreshOnUpstreamUnauthorized`)
- Slides the session's idle timeout on every request; enforces the absolute
  session lifetime
- Optional pass-through of requests without a session cookie to a later
  authentication policy (`continueWithoutCookie`)
- Headers only: request and response bodies are never buffered, so streamed
  and proxied responses pass straight through
- Fails closed when Redis is unavailable

## Configuration

### User Parameters (API Definition)

The session settings must be the same as on the OAuth2 Session attachment
that logs users in. With a different key or cookie setting, every session
looks invalid here and every request gets `401`.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tokenEndpoint` | string | Yes | - | Identity provider token endpoint used to refresh access tokens. Same as in OAuth2 Session. |
| `clientId` | string | Yes | - | OAuth client ID. Same as in OAuth2 Session; it is also recorded in the `AuthContext`. |
| `clientSecret` | string | Yes | - | Client secret paired with `clientId`. Supply it as a secret reference, e.g. `'{{ secret "handle" }}'`. |
| `sessionSigningKey` | string | Yes | - | Same secret as in OAuth2 Session; verifies the session cookie. |
| `tokenEncryptionKey` | string | Yes | - | Same secret as in OAuth2 Session; decrypts and re-encrypts the tokens in Redis. |
| `clientAuthMethod` | string | No | `"client_secret_basic"` | How client credentials are sent to the token endpoint: `"client_secret_basic"` or `"client_secret_post"`. |
| `idleTimeout` | string | No | `"30m"` | Every request extends the session's idle timeout by this much (Go duration format). Use the same value as in OAuth2 Session. |
| `absoluteSessionTimeout` | string | No | `"8h"` | Maximum age of a session regardless of activity (Go duration format), and the lifetime of a re-issued session cookie. Use the same value as in OAuth2 Session. |
| `continueWithoutCookie` | boolean | No | `false` | When `true`, a request that carries no session cookie continues unchanged to the next policies instead of getting `401`. A request with the cookie is still checked here. See [Browsers and API Clients on One API](#browsers-and-api-clients-on-one-api). |
| `upstreamHeaderName` | string | No | `"Authorization"` | Header on the backend request that carries the access token. |
| `upstreamValuePrefix` | string | No | `"Bearer"` | Prefix placed before the access token, separated by a space. Set `""` for no prefix. |
| `refreshOnUpstreamUnauthorized` | boolean | No | `true` | When the backend answers `401`, mark the access token it rejected as expired so the next request refreshes it. The `401` itself still reaches the client. See [Backend `401`](#backend-401). |
| `upstreamUnauthorizedCooldown` | string | No | `"30s"` | A backend `401` is ignored for an access token obtained less than this long ago, so a backend that rejects every token can't make each request refresh (Go duration format). |
| `cookie.name` | string | No | `"X-ABC"` | Session cookie name. Same as in OAuth2 Session. |
| `cookie.stateCookieName` | string | No | `"X-ABC-state"` | Login state cookie name, removed from the backend request. Same as in OAuth2 Session. |
| `cookie.sameSite` | string | No | `"Lax"` | `SameSite` attribute of a re-issued session cookie. Same as in OAuth2 Session. |
| `cookie.secure` | boolean | No | `true` | `Secure` attribute of a re-issued session cookie. Same as in OAuth2 Session. |
| `refreshBuffer` | string | No | `"5m"` | How long before expiry the access token is refreshed (Go duration format). `0` refreshes only once expired. |
| `defaultTokenTTL` | string | No | `"1h"` | Access token lifetime assumed when a refresh response omits `expires_in`. |
| `tokenRequestTimeout` | string | No | `"10s"` | Timeout for one token endpoint call (Go duration format). |
| `tokenRequestMaxRetries` | integer | No | `2` | Retries after a `429` or `5xx` from the token endpoint, with exponential backoff and jitter. Network errors are not retried. |
| `proxyURL` | string | No | `""` | Proxy for token endpoint calls. Defaults to the `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables. |
| `tlsCaCert` | string | No | `""` | PEM CA certificate content to trust for the token endpoint's TLS connection, supplied as a secret reference. |
| `tlsInsecureSkipVerify` | boolean | No | `false` | Disables TLS verification for the token endpoint. Local testing only. |

### System Parameters (From config.toml)

The policy uses the same Redis settings as OAuth2 Session, from
`policy_configurations.oauth2_session_v0.redis`, so both reach the same
records. See
[OAuth2 Session system parameters](../../../oauth2-session/v0.1/docs/oauth2-session.md#system-parameters-from-configtoml).

## API Setup

Attach OAuth2 Session to its own operations and this policy to every
operation that reaches the backend. A proxy API usually has a few auth
operations and one wildcard per method:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: console-api
spec:
  displayName: console-api
  version: v1
  context: /api
  upstream:
    main:
      url: http://console-backend:8080
  operations:
    # Answered by oauth2-session.
    - method: GET
      path: /auth/signin
      policies:
        - &session
          name: oauth2-session
          version: v0
          params:
            authorizationEndpoint: https://idp.example.com/oauth2/authorize
            tokenEndpoint: https://idp.example.com/oauth2/token
            clientId: console
            clientSecret: '{{ secret "console-client-secret" }}'
            redirectUri: https://console.example.com/api/auth/callback
            scopes: [openid, profile, email]
            loginPath: /auth/signin
            callbackPath: /auth/callback
            logoutPath: /auth/signout
            userinfoPath: /auth/session
            sessionSigningKey: '{{ secret "console-session-signing-key" }}'
            tokenEncryptionKey: '{{ secret "console-token-encryption-key" }}'
    - {method: GET, path: /auth/callback, policies: [*session]}
    - {method: GET, path: /auth/session, policies: [*session]}
    - {method: POST, path: /auth/signout, policies: [*session]}

    # Everything else is proxied to the backend with the session's access token.
    - method: GET
      path: /*
      policies:
        - &proxy
          name: oauth2-session-proxy
          version: v0
          params:
            tokenEndpoint: https://idp.example.com/oauth2/token
            clientId: console
            clientSecret: '{{ secret "console-client-secret" }}'
            sessionSigningKey: '{{ secret "console-session-signing-key" }}'
            tokenEncryptionKey: '{{ secret "console-token-encryption-key" }}'
    - {method: POST, path: /*, policies: [*proxy]}
    - {method: PUT, path: /*, policies: [*proxy]}
    - {method: PATCH, path: /*, policies: [*proxy]}
    - {method: DELETE, path: /*, policies: [*proxy]}
```

The router prefers the exact auth operations over the wildcard, so
`/api/auth/signin` reaches OAuth2 Session and everything else reaches this
policy. Operations without either policy, such as a health check, stay
public.

### Browsers and API Clients on One API

By default a request without a session cookie gets `401`. Set
`continueWithoutCookie: true` to let such a request continue instead, and
attach the policy that authenticates API clients (for example JWT or API key
authentication) **after** this one:

| Request | What happens |
|---------|--------------|
| Carries the session cookie, session valid | Authenticated here; the bearer token is set for the backend |
| Carries the session cookie, session not valid (forged, expired, logged out, duplicate cookie) | `401` here; it does not fall through |
| No session cookie | Passed on unchanged; this policy sets no header and leaves the `AuthContext` as it was |

The cookie decides who handles the request, so a stale browser cookie can't
be used to slip past to another policy. With this option on, the operation
is only protected if a later policy authenticates the requests that have no
cookie: without one, they reach the backend unauthenticated.

## How It Works

### Every request

1. The session cookie is read; exactly one cookie of that name must be
   present. With `continueWithoutCookie`, a request without the cookie
   continues to the next policies here, unchanged. The cookie's signature is
   checked before Redis is contacted, so forged cookies cost no Redis
   lookup.
2. The session is loaded from Redis and its idle timeout extended in the same
   call. Sessions older than `absoluteSessionTimeout` are deleted.
3. If the access token expires within `refreshBuffer`, it is refreshed, as
   described in
   [OAuth2 Session: Refresh](../../../oauth2-session/v0.1/docs/oauth2-session.md#refresh).
4. The access token is set in `upstreamHeaderName`, the session and state
   cookies are removed from the `Cookie` header sent to the backend (other
   cookies are kept), and the request is forwarded. The shared
   `AuthContext` records `AuthType` `oauth2-session`, the client ID and the
   granted scopes for later policies.
5. If the token was refreshed, the session cookie is re-issued on the
   backend's response with `Set-Cookie`, appended to any the backend sent.
6. If the backend answers `401`, the access token is marked as expired (see
   [Backend `401`](#backend-401)).

### Backend `401`

Refresh is normally driven by the token's `expires_in`. If the backend
rejects a token earlier (revoked at the identity provider, or a wrong
`expires_in`), the policy reacts to the backend's `401`:

1. The `401` response goes to the client unchanged. The policy can't replay
   the request with a new token, so the client retries.
2. The session's access token is marked as expired in Redis. The record is
   changed only while it still holds the rejected token (a Redis `WATCH`
   transaction), so a token another request has already refreshed is never
   touched, and the record keeps its TTL.
3. The next request for the session refreshes the token with the refresh
   token. If the refresh token is no longer valid, or there is none, the
   session ends and the request gets `401`.

Only `401` triggers this; `403`, `404` and other statuses don't. A token
obtained less than `upstreamUnauthorizedCooldown` ago is never marked, so a
backend that rejects every token causes at most one refresh per cooldown
period instead of one per request. Set `refreshOnUpstreamUnauthorized:
false` to turn this off.

## Error Responses

All error responses are JSON (`Content-Type: application/json`) and carry
`Cache-Control: no-store`. Responses from the backend are passed through.

| Scenario | Status | Body `error` |
|----------|--------|--------------|
| No session cookie (unless `continueWithoutCookie`), forged or duplicate cookie, unknown, idle or expired session | 401 | `unauthorized` |
| Refresh token rejected by the identity provider | 401 | `unauthorized` |
| Redis unavailable | 503 | `service_unavailable` |
| Identity provider unavailable and the access token has expired | 503 | `service_unavailable` |

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

- **Same keys, same Redis** – this policy can only read sessions created by
  an OAuth2 Session attachment with the same `sessionSigningKey`,
  `tokenEncryptionKey` and Redis `keyPrefix`. Supply the keys as secret
  references, and share them only between attachments of the same client.
- **Cross-site requests** – the session cookie is `SameSite=Lax` by default,
  so browsers don't send it with cross-site `POST`, `PUT`, `PATCH` or
  `DELETE` requests. Keep state-changing backend operations off `GET`, or
  use `cookie.sameSite: Strict` on both policies.
- **The access token never reaches the browser** – it is set only on the
  upstream request. Backends must not echo the `Authorization` header back.
- **`continueWithoutCookie`** – only safe with a later authentication
  policy on the same operations.
- **`tlsInsecureSkipVerify`** – for local testing only.

## Gateway Module Reference

```yaml
- name: oauth2-session-proxy
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-session-proxy@v0
```
