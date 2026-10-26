# Login with OpenID Connect

`OidcPlugin` lets users log in with an OpenID Connect provider such as Microsoft Entra ID, Keycloak or Google. It builds on
[users and login](users.md): a login with a provider ends in the same session as a login with an email link.

```kotlin
val users = UsersPlugin(UsersSettings<Ctx, Views>(/* ... */, emailLogin = false))
val rbac = RbacPlugin(users)
val oidc = OidcPlugin(
    users,
    listOf(OidcProvider.entra(tenantId, clientId, clientSecret, roleMapping = mapOf("app-admin" to "Admin"))),
    rbac,
)

val specification = SpecificationBuilder<Ctx, Views>(views).build {
    plugins(users, rbac, oidc)
    // ...
}

routing {
    usersRoutes(support, users, loginOptions = oidc.loginOptions())
    oidcRoutes(support, users, oidc)
}
```

Register this redirect address at the provider: `<baseUrl>/login/oidc/<key>/callback`, where `baseUrl` is the one in
`UsersSettings` and `key` is the key of the provider (`entra` for `OidcProvider.entra`).

The plugin uses the authorization code flow with PKCE. It verifies the ID token: the signature against the provider's keys,
the issuer, the audience, the expiry and the nonce of the login. A login can only be finished once, and only in the browser
that started it.

## Who is the user

A user is identified by the provider's key and the value of one claim, `subjectClaim` (`sub` by default, `oid` for Entra).
It must be a claim that never changes for a user. Never use an email address, which can be changed or reused.

The first time someone logs in, no user has their identity yet. What happens is decided by the provider:

* `linkBy = LinkBy.None` (default): nothing is linked. The identity gets in only through `provisionUsers`.
* `linkBy = LinkBy.Email`: the identity is linked to the user whose email address is the `email` claim (or
  `preferred_username` if there is no `email`). From then on the identity is what identifies the user. A user that already
  has another identity at the provider is not linked.
* `provisionUsers = true`: a user is created, with the name and email address from the claims. It requires a `roleMapping`,
  and the token must have at least one value in it: the provider decides who may use the application. An address that
  belongs to another user is not taken over.

`LinkBy.Email` is only safe if the provider's administrators control the address. That is the case for the single tenant of an
organization, and not for a provider where users can choose their own address.

A disabled user cannot log in. The name of the user is updated at every login; the email address never is.

## Roles

`roleClaim` is the claim that holds the user's roles, such as `roles` or `groups`. `roleMapping` translates its values to the
names of roles in the application. Other values are ignored. `roleSync` says how the result relates to the roles an
administrator gave, see [roles from an identity provider](rbac.md):

* `RoleSync.App` (default): the provider's roles are ignored.
* `RoleSync.Additive`: the provider's roles are added and taken away. Roles an administrator gave stay.
* `RoleSync.Authoritative`: the provider decides. A login fails if the token has no value in `roleMapping`.

The superadmin role is only given or taken by the mapping with `allowSuperadminMapping = true`, and the last enabled
superadmin is never demoted. To be sure that someone can always get in, call `rbac.ensureSuperadmin(email, name)` at startup
with `linkBy = LinkBy.Email`.

If `roleClaim` is `groups` and the user is in too many groups for the provider to list them (Entra: more than 200), the
login fails with a clear message. Use app roles instead.

## Microsoft Entra ID

`OidcProvider.entra(tenantId, clientId, clientSecret, roleMapping)` is set up for one tenant:

* Only tokens from the tenant are accepted (the issuer and the `tid` claim).
* The user is identified by the `oid` claim.
* Roles come from the `roles` claim: define app roles on the app registration and assign them to users or groups. With a
  `roleMapping`, `roleSync` is `Authoritative`.

Create the app registration with a web redirect address as above and a client secret. Entra's `email` claim is not
verified, so the default is `LinkBy.None`; use `LinkBy.Email` only for a tenant whose administrators control the attribute.

## When the user is disabled at the provider

The application does not hear about it by itself. A session ends when:

* `sessionLifetime` (8 hours) has passed. The user is then sent to the provider again, which does not ask for anything if their
  session there lives, and refuses if the account is disabled.
* `refreshCheckInterval` is set: the provider is asked this often, with the refresh token, whether the user may still log in,
  and the session ends when it refuses. The tokens are kept in memory, so sessions are not checked after a restart. Not on by default.
* `frontChannelLogout = true`: the user logs out at the provider. Register
  `<baseUrl>/login/oidc/<key>/frontchannel-logout` as the front-channel logout address. It is called in the browser, so it
  does not reach a user that is disabled by an administrator. Entra has no back-channel logout.

## Settings

| Setting                  | Default       | What                                                                      |
|--------------------------|---------------|---------------------------------------------------------------------------|
| `key`                    |               | Identifies the provider. Lower case letters, digits and `-`.              |
| `issuer`                 |               | The `https://` address of the provider, with `/.well-known/openid-configuration`. |
| `clientId`, `clientSecret` |             | The application's credentials at the provider.                            |
| `label`                  | `key`         | Shown on the button.                                                      |
| `scopes`                 | profile, email | `openid` is always requested.                                            |
| `subjectClaim`           | `sub`         | The claim that identifies the user.                                       |
| `linkBy`                 | `None`        | How a new identity gets to an existing user.                              |
| `provisionUsers`         | false         | Whether a new user is created at the first login.                         |
| `roleClaim`, `roleMapping`, `roleSync` | `App` | Roles from the provider.                                          |
| `allowSuperadminMapping` | false         | Whether the mapping may give and take the superadmin role.                |
| `sessionLifetime`        | 8 hours       | How long a login lasts.                                                   |
| `refreshCheckInterval`   | none          | How often the provider is asked whether the user may still log in.       |
| `frontChannelLogout`     | false         | Whether the provider may end sessions.                                    |
| `requiredClaims`         | none          | Claims the ID token must have, with their values.                         |
| `signingAlgorithm`       | `RS256`       | How the provider signs ID tokens.                                         |

The plugin owns the model `AuthOidcFlow`, and `AuthIdentity` comes from `UsersPlugin`. Your application must not declare
models with those names.
