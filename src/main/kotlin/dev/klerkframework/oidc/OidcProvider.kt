package dev.klerkframework.oidc

import dev.klerkframework.webextra.auth.RoleSync
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

/** What happens when someone logs in with an identity that is not linked to a user yet. */
public enum class LinkBy {
    /** Nothing is linked. Only [OidcProvider.provisionUsers] can let such an identity in. */
    None,

    /**
     * The identity is linked to the user whose email address is the `email` claim (or `preferred_username` if there is
     * no `email`), once. After that the identity is what identifies the user.
     *
     * Only safe if the provider's administrators control the address, which is the case for the single tenant of an
     * organization, and not for providers where users can choose their own address.
     */
    Email,
}

/**
 * An OpenID Connect provider that users can log in with. Use [entra] for Microsoft Entra ID.
 *
 * ```kotlin
 * OidcProvider(
 *     key = "keycloak",
 *     issuer = "https://id.example.com/realms/main",
 *     clientId = "my-app",
 *     clientSecret = System.getenv("OIDC_SECRET"),
 * )
 * ```
 *
 * An identity is the pair of [key] and the value of [subjectClaim]. Roles are given from the claim [roleClaim] according
 * to [roleMapping] and [roleSync].
 */
public data class OidcProvider(
    /** Identifies the provider, in the address of the login and in the stored identities. Never change it. */
    val key: String,
    /** The `https://` address of the provider. `<issuer>/.well-known/openid-configuration` must exist. */
    val issuer: String,
    val clientId: String,
    val clientSecret: String,
    /** Shown on the login button: "Log in with $label". */
    val label: String = key,
    /** `openid` is always requested, and `offline_access` if [refreshCheckInterval] is set. */
    val scopes: Set<String> = setOf("profile", "email"),
    /** The claim that identifies the user. Must never change for a user, which excludes email addresses. */
    val subjectClaim: String = "sub",
    /** What to do with an identity that is not linked to a user. */
    val linkBy: LinkBy = LinkBy.None,
    /**
     * Whether someone who logs in for the first time gets a user, provided the token carries at least one value in
     * [roleMapping]. Requires a non-empty [roleMapping]: who may use the application is then decided by the provider.
     */
    val provisionUsers: Boolean = false,
    /** The claim that holds the user's roles, e.g. `roles` (Entra app roles) or `groups`. */
    val roleClaim: String? = null,
    /** Translates a value of [roleClaim] to the name of a role in the application. Other values are ignored. */
    val roleMapping: Map<String, String> = emptyMap(),
    /**
     * How the roles from the provider relate to the roles given in the application. With [RoleSync.Authoritative] a
     * login fails if the token has no value in [roleMapping], since the provider then says the user has no access.
     */
    val roleSync: RoleSync = RoleSync.App,
    /** Whether [roleMapping] may give and take the superadmin role. The last enabled superadmin is never demoted. */
    val allowSuperadminMapping: Boolean = false,
    /** How long a login lasts. Then the user is sent to the provider again, which is silent if their session there lives. */
    val sessionLifetime: Duration = 8.hours,
    /**
     * If set, the provider is asked this often whether the user may still log in, using the refresh token, and the
     * session ends when it says no. The refresh tokens are kept in memory, so after a restart the sessions are not
     * checked any more and end with their lifetime. Null means no checks.
     */
    val refreshCheckInterval: Duration? = null,
    /**
     * Whether the provider may end sessions by calling `<login>/oidc/<key>/frontchannel-logout` in the user's browser
     * when the user logs out there. Register that address at the provider. It only reaches sessions where the user logs
     * out; a user that is disabled at the provider is found by [refreshCheckInterval] or at the end of the session.
     */
    val frontChannelLogout: Boolean = false,
    /** Claims that the ID token must have, with the values they must have. */
    val requiredClaims: Map<String, String> = emptyMap(),
    /** The algorithm the provider signs ID tokens with. */
    val signingAlgorithm: String = "RS256",
) {
    init {
        require(key.matches(Regex("[a-z0-9-]{1,50}"))) { "key '$key' must be lower case letters, digits and -" }
        require(
            issuer.startsWith("https://") ||
                issuer.startsWith("http://localhost") ||
                issuer.startsWith("http://127.0.0.1"),
        ) { "issuer must be an https:// address, but was '$issuer'" }
        require(clientId.isNotBlank()) { "clientId is empty" }
        require(clientSecret.isNotBlank()) { "clientSecret is empty" }
        require(roleSync == RoleSync.App || roleClaim != null) { "roleSync $roleSync needs a roleClaim" }
        require(roleSync != RoleSync.Authoritative || roleMapping.isNotEmpty()) { "Authoritative needs a roleMapping" }
        require(!provisionUsers || roleMapping.isNotEmpty()) { "provisionUsers needs a roleMapping" }
        require(refreshCheckInterval == null || refreshCheckInterval.isPositive()) {
            "refreshCheckInterval is not positive"
        }
    }

    override fun toString(): String = "OidcProvider(key=$key, issuer=$issuer, clientId=$clientId)"

    public companion object {
        /**
         * Microsoft Entra ID for the single tenant [tenantId]. Only tokens from that tenant are accepted, the user is
         * identified by the `oid` claim (never by an email address, which an Entra user may be able to change), and
         * roles come from the app roles in the `roles` claim. [roleSync] is [RoleSync.Authoritative] if there is a
         * [roleMapping], so that what is assigned in Entra decides.
         *
         * Define the roles on the app registration and assign them to users or groups. Use `groups` as the claim only if
         * a user cannot be in more than 200 groups: past that limit Entra leaves the claim out and the login fails.
         */
        public fun entra(
            tenantId: String,
            clientId: String,
            clientSecret: String,
            roleMapping: Map<String, String> = emptyMap(),
            key: String = "entra",
            label: String = "Microsoft",
            roleClaim: String = "roles",
            roleSync: RoleSync = if (roleMapping.isEmpty()) RoleSync.App else RoleSync.Authoritative,
            linkBy: LinkBy = LinkBy.None,
            provisionUsers: Boolean = false,
            allowSuperadminMapping: Boolean = false,
            sessionLifetime: Duration = 8.hours,
            refreshCheckInterval: Duration? = null,
            frontChannelLogout: Boolean = false,
        ): OidcProvider {
            require(tenantId.matches(Regex("[0-9a-fA-F-]{36}"))) { "tenantId must be the GUID of the tenant" }
            return OidcProvider(
                key = key,
                issuer = "https://login.microsoftonline.com/$tenantId/v2.0",
                clientId = clientId,
                clientSecret = clientSecret,
                label = label,
                subjectClaim = "oid",
                linkBy = linkBy,
                provisionUsers = provisionUsers,
                roleClaim = roleClaim,
                roleMapping = roleMapping,
                roleSync = roleSync,
                allowSuperadminMapping = allowSuperadminMapping,
                sessionLifetime = sessionLifetime,
                refreshCheckInterval = refreshCheckInterval,
                frontChannelLogout = frontChannelLogout,
                requiredClaims = mapOf("tid" to tenantId.lowercase()),
            )
        }
    }
}
