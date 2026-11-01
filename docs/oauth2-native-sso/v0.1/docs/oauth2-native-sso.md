---
title: "Overview"
---
# OAuth2 Native SSO

## Overview

The **OAuth2 Native SSO** policy signs a browser in to one API (the
**target**) from the [OAuth2 Session](../../../oauth2-session/v0.1/docs/oauth2-session.md)
login it already has on another API (the **source**), without sending the
user back to the identity provider. It uses the token exchange of
[OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html):
the source session's `id_token` and `device_secret` are exchanged at the
token endpoint for tokens of the target's OAuth client.

The tokens are stored in Redis as a brand-new OAuth2 Session session, and
the browser receives the target's session cookie in a redirect. From then
on the target API's own OAuth2 Session policy serves that session as if the
user had logged in to it directly: it refreshes tokens, sends the bearer
token to the backend, and handles userinfo, logout and back-channel logout.

## Features

- Native SSO token exchange (`subject_token` = `id_token`, `actor_token` =
  `device_secret`) with `client_secret_basic` or `client_secret_post`
- Creates a session in OAuth2 Session's own format, so no change to the
  target API's OAuth2 Session policy is needed
- SSO on the login path, and optionally on any request (`transparentSso`)
- The new session never outlives the source session
- A `device_secret` rotated by the identity provider is written back to the
  source session
- With `issuer` set, the returned `id_token` must come from the issuer, be
  issued to this client and belong to the same identity provider session as
  the source; the new session is indexed for back-channel logout
- Concurrent requests of one browser cause one exchange, and all get the
  same session
- Never blocks a request: whenever SSO isn't possible the request continues
  to OAuth2 Session, which runs its normal login

## Prerequisites

- **Both APIs use OAuth2 Session** on the same gateway host, with different
  session cookie names. Session cookies are host-only with `Path=/`, so the
  browser sends the source cookie to the target API.
- **The source session holds a `device_secret`.** The source login must
  request the `device_sso` scope. OAuth2 Session stores the returned
  `device_secret` in the session record (`device_secret` member) and keeps
  it across refreshes.
- **The identity provider supports Native SSO** for the target client and
  allows it to exchange the source client's `id_token` and `device_secret`.
- **The same Redis, database and key prefix** as OAuth2 Session. The policy
  reads `policy_configurations.oauth2_session_v0.redis` by default.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tokenEndpoint` | string | Yes | - | Token endpoint that performs the exchange. `https://` unless `allowInsecureTokenEndpoint` is set. |
| `clientId` | string | Yes | - | Target client ID; the same as the target's OAuth2 Session `clientId`. |
| `clientSecret` | string | Yes | - | Target client secret. Use `{{ secret "handle" }}`. |
| `clientAuthMethod` | string | No | `"client_secret_basic"` | `client_secret_basic` or `client_secret_post`. |
| `scopes` | string array | No | `["openid"]` | Scopes requested in the exchange. |
| `issuer` | string | No | `""` | Identity provider issuer. Enables the `id_token` checks and the back-channel logout index, and is the default `audience`. |
| `audience` | string | No | `issuer` | `audience` of the exchange; Native SSO requires the issuer. Required when `issuer` is not set. |
| `resource` | string | No | `""` | RFC 8707 resource indicator sent in the exchange, so the access token is for that API. Use the `resource` the target API's own login requests (for example in its `authorizationRequestParams`). Not sent when empty. |
| `subjectToken` | string | No | `"id_token"` | Source session token sent as `subject_token`: `id_token` or `device_secret`. See [Token exchange layout](#token-exchange-layout). |
| `subjectTokenType` | string | No | per token | `subject_token_type` (an absolute URI). Defaults to `urn:ietf:params:oauth:token-type:id_token` for the `id_token` and `urn:openid:params:token-type:device-secret` for the `device_secret`. |
| `actorToken` | string | No | the other token | Source session token sent as `actor_token`: `id_token`, `device_secret`, or `none` to send none. One of `subjectToken` and `actorToken` must be `device_secret`. |
| `actorTokenType` | string | No | per token | `actor_token_type` (an absolute URI), with the same per-token defaults. Not allowed when `actorToken` is `none`. |
| `loginPath` | string | No | `"/login"` | The target OAuth2 Session login operation path. |
| `postLoginRedirect` | string | No | `"/"` | Where users land after SSO without a valid `returnTo`. Include the API context. |
| `transparentSso` | boolean | No | `false` | Also sign in on other operations, answering `307` to the same path. |
| `source.cookieName` | string | Yes | - | Session cookie name of the source OAuth2 Session policy. |
| `source.sessionSigningKey` | string | Yes | - | The source OAuth2 Session `sessionSigningKey`. |
| `source.tokenEncryptionKey` | string | Yes | - | The source OAuth2 Session `tokenEncryptionKey`. |
| `source.absoluteSessionTimeout` | string | No | `"8h"` | The source OAuth2 Session `absoluteSessionTimeout`. |
| `target.cookieName` | string | Yes | - | The target OAuth2 Session `cookie.name`. Must differ from `source.cookieName`. |
| `target.sessionSigningKey` | string | Yes | - | The target OAuth2 Session `sessionSigningKey`. |
| `target.tokenEncryptionKey` | string | Yes | - | The target OAuth2 Session `tokenEncryptionKey`. |
| `target.idleTimeout` | string | No | `"30m"` | The target OAuth2 Session `idleTimeout`. |
| `target.absoluteSessionTimeout` | string | No | `"8h"` | The target OAuth2 Session `absoluteSessionTimeout`. |
| `target.sameSite` | string | No | `"Lax"` | The target OAuth2 Session `cookie.sameSite`. |
| `target.secure` | boolean | No | `true` | The target OAuth2 Session `cookie.secure`. |
| `defaultTokenTTL` | string | No | `"1h"` | Access token lifetime when the response has no `expires_in`. |
| `tokenRequestTimeout` | string | No | `"10s"` | Timeout for one token endpoint call. |
| `tokenRequestMaxRetries` | integer | No | `2` | Retries after a `429` or `5xx`. Network errors are not retried. |
| `allowInsecureTokenEndpoint` | boolean | No | `false` | Allow an `http://` token endpoint. Local testing only. |
| `proxyURL` | string | No | `""` | Proxy for token endpoint calls; defaults to `HTTP_PROXY`/`HTTPS_PROXY`. |
| `tlsCaCert` | string | No | `""` | PEM CA certificate trusted for the token endpoint. |
| `tlsInsecureSkipVerify` | boolean | No | `false` | Disable TLS verification of the token endpoint. Non-production only. |

The `source.*` and `target.*` values must equal the corresponding OAuth2
Session parameters, or the cookies and Redis records won't be readable by
the other policy. Keys are derived from the secrets exactly as OAuth2
Session derives them.

### System Parameters (From config.toml)

Redis settings resolve from OAuth2 Session's section,
`policy_configurations.oauth2_session_v0.redis`, so a gateway configured for
OAuth2 Session needs nothing more. The parameters are the same as OAuth2
Session's; `keyPrefix` in particular must match.

## How It Works

1. A `GET` to `loginPath` (or, with `transparentSso`, any request) arrives
   without a live target session but with a valid source session cookie.
2. The source session is read from Redis without extending its idle
   timeout. A session past `source.absoluteSessionTimeout`, or without an
   `id_token` or `device_secret`, is not used.
3. The policy sends the token exchange:

   ```
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   audience=<audience>
   subject_token=<source id_token>
   subject_token_type=urn:ietf:params:oauth:token-type:id_token
   actor_token=<source device_secret>
   actor_token_type=urn:openid:params:token-type:device-secret
   scope=<scopes>
   resource=<resource>        (only when configured)
   client_id=<clientId>
   ```

4. A new session with a fresh random ID is written in OAuth2 Session's
   format, encrypted with the target key, with the returned `device_secret`
   (or the source's). Its login time is moved back if needed so that the
   target's absolute timeout ends it no later than the source session.
5. The browser receives a `302` to `returnTo` (or `postLoginRedirect`), or a
   `307` to the same path with `transparentSso`, setting the target session
   cookie. The next request is handled by the target's OAuth2 Session.

### Token exchange layout

By default the exchange follows OpenID Connect Native SSO for Mobile Apps
1.0 §4, shown above: the `id_token` is the subject and the `device_secret`
the actor. Identity providers that implement Native SSO differently are
configured with `subjectToken`, `subjectTokenType`, `actorToken` and
`actorTokenType`. For example, ThunderID takes the `device_secret` alone, as
a JWT subject:

```yaml
subjectToken: device_secret
subjectTokenType: urn:ietf:params:oauth:token-type:jwt
actorToken: none
```

which sends `subject_token=<device_secret>`,
`subject_token_type=urn:ietf:params:oauth:token-type:jwt` and no
`actor_token`. Whatever the layout, the returned `id_token` is checked
against the source session as described below when `issuer` is set.

If any step fails, the request continues unchanged: on the login path
OAuth2 Session redirects to the identity provider, and elsewhere it answers
`401`. Failures are logged internally only.

## Reference Scenarios

### Example: Billing API Signed In from the Orders API Login

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: billing-web
spec:
  displayName: billing-web
  version: v1
  context: /billing/$version
  upstream:
    main:
      url: http://billing-backend:8080
  policies:
    - name: oauth2-native-sso
      version: v0
      params:
        tokenEndpoint: https://idp.example.com/oauth2/token
        clientId: billing-web
        clientSecret: '{{ secret "billing-web-client-secret" }}'
        issuer: https://idp.example.com
        scopes: [openid, billing:read]
        postLoginRedirect: /billing/v1/
        source:
          cookieName: __Host-orders
          sessionSigningKey: '{{ secret "orders-session-signing" }}'
          tokenEncryptionKey: '{{ secret "orders-token-encryption" }}'
        target:
          cookieName: __Host-billing
          sessionSigningKey: '{{ secret "billing-session-signing" }}'
          tokenEncryptionKey: '{{ secret "billing-token-encryption" }}'
    - name: oauth2-session
      version: v0
      params:
        # ... clientId billing-web, cookie.name __Host-billing, the same
        # signing/encryption secrets and timeouts as target above
  operations:
    - method: GET
      path: /login
    - method: GET
      path: /callback
    - method: GET
      path: /logout
    - method: GET
      path: /invoices
```

A user signed in to the orders API who opens `/billing/v1/login` lands on
`/billing/v1/` signed in to billing, without seeing the identity provider.

## Security Considerations

- **Logging out of the target alone can be undone.** While the source
  session and its `device_secret` are valid, the next SSO signs the user in
  again. Configure the target's `endSessionEndpoint` so logout ends the
  identity provider session, which also invalidates the `device_secret`.
- **The source secrets are shared with this policy.** Anyone who can read
  this API definition can read the source API's sessions; reference them as
  secrets.
- **Tokens and the `device_secret` are never logged** and never sent to the
  browser; only the opaque signed session cookie is.
- **Redirects stay on the same origin**: `returnTo` must be a relative path,
  and the `307` goes back to the request's own path. Redirects from the
  token endpoint are not followed.
- **Symmetric primitives only** (HMAC-SHA3-256 cookies, AES-256-GCM
  records), as in OAuth2 Session.

## Gateway Module Reference

```yaml
- name: oauth2-native-sso
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-native-sso@v0
```
