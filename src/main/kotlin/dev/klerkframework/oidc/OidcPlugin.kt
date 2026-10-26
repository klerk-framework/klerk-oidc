package dev.klerkframework.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.oauth2.sdk.AuthorizationCode
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant
import com.nimbusds.oauth2.sdk.RefreshTokenGrant
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.TokenResponse
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator
import dev.klerkframework.klerk.CommandResult
import dev.klerkframework.klerk.Klerk
import dev.klerkframework.klerk.KlerkContext
import dev.klerkframework.klerk.KlerkPlugin
import dev.klerkframework.klerk.ManagedModel
import dev.klerkframework.klerk.ModelID
import dev.klerkframework.klerk.Specification
import dev.klerkframework.klerk.command.Command
import dev.klerkframework.webextra.auth.AuthPaths
import dev.klerkframework.webextra.auth.ExpiresAt
import dev.klerkframework.webextra.auth.IssuedSession
import dev.klerkframework.webextra.auth.LoginOption
import dev.klerkframework.webextra.auth.ProviderKey
import dev.klerkframework.webextra.auth.RbacPlugin
import dev.klerkframework.webextra.auth.RoleSync
import dev.klerkframework.webextra.auth.TokenHash
import dev.klerkframework.webextra.auth.User
import dev.klerkframework.webextra.auth.UsersPlugin
import dev.klerkframework.webextra.auth.logIn
import io.ktor.server.application.ApplicationCall
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mu.KotlinLogging
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

private val logger = KotlinLogging.logger {}

private const val HTTP_CONNECT_TIMEOUT_MS = 5_000
private const val HTTP_READ_TIMEOUT_MS = 10_000
private const val JWKS_SIZE_LIMIT = 200_000
private val flowValidity = 10.minutes
private val metadataValidity = 60.minutes
private val refreshTickInterval = 30_000L

/** Why a login with an identity provider failed. [message] is safe to show to the user. */
public enum class OidcRejection(public val message: String) {
    /** The request did not belong to a login that was started in this browser, or it had been used already. */
    InvalidRequest("The login could not be completed. Please try again."),

    /** The provider answered with an error, or could not be reached. */
    ProviderError("The login provider could not log you in. Please try again."),

    /** The ID token was not valid. */
    InvalidToken("The login provider's answer was not accepted."),

    /** The identity belongs to nobody and nothing lets it in. */
    NotInvited("You do not have access to this application."),

    /** The token has none of the roles that give access. */
    MissingRole("You do not have access to this application."),

    /** The user has too many groups for the provider to list them in the token. */
    GroupsOverage("The login provider listed too many groups to be used. Contact an administrator."),

    /** The user is disabled. */
    UserDisabled("Your account is disabled."),

    /** The provider does not say what email address the user has, or it belongs to someone else. */
    EmailProblem("Your account could not be created. Contact an administrator."),
}

/** The result of [OidcPlugin.completeLogin]. */
public sealed class OidcLoginResult {

    /** The user is who the provider says. Call [OidcPlugin.finishLogin] to give the browser a session. */
    public class LoggedIn internal constructor(
        public val user: ModelID<User>,
        public val provider: OidcProvider,
        internal val providerSessionId: String?,
        internal val refreshToken: String?,
    ) : OidcLoginResult()

    /** The login failed for [reason]. */
    public class Rejected internal constructor(public val reason: OidcRejection) : OidcLoginResult()
}

/** Where to send the browser to log in at the provider, and the cookie to set before that. */
public class OidcLoginStart internal constructor(public val redirectUrl: String, public val flowCookie: String)

/**
 * Login with OpenID Connect providers, using the authorization code flow with PKCE. Add it to the specification
 * after [UsersPlugin] (and [RbacPlugin], if roles come from the provider) and add the pages with [oidcRoutes].
 *
 * ```kotlin
 * val oidc = OidcPlugin(users, listOf(OidcProvider.entra(tenantId, clientId, secret, roleMapping)), rbac)
 * plugins(users, rbac, oidc)
 * // ...
 * usersRoutes(support, users, loginOptions = oidc.loginOptions())
 * oidcRoutes(support, users, oidc)
 * ```
 *
 * The ID token is verified: its signature against the provider's keys, issuer, audience, expiry and the nonce of the
 * login. Users are identified by the pair of provider and subject claim, see [OidcProvider.linkBy] for how an identity
 * gets to a user.
 *
 * The redirect address to register at the provider is `<baseUrl><paths.login>/oidc/<key>/callback`, with the
 * [dev.klerkframework.webextra.auth.UsersSettings.baseUrl] of [users].
 */
public class OidcPlugin<C : KlerkContext, V>(
    private val users: UsersPlugin<C, V>,
    providers: List<OidcProvider>,
    private val rbac: RbacPlugin<C, V>? = null,
    /** Must be the same [AuthPaths] as the one given to `usersRoutes`. */
    public val paths: AuthPaths = AuthPaths(),
) : KlerkPlugin<C, V> {

    override val name: String = "AuthOidc"

    override val description: String = "Login with OpenID Connect."

    /** The providers by [OidcProvider.key]. */
    public val providers: Map<String, OidcProvider> = providers.associateBy { it.key }

    /** The views of [AuthOidcFlow]. */
    public val flowViews: AuthOidcFlowViews<C> = AuthOidcFlowViews()

    private lateinit var klerk: Klerk<C, V>
    private val clients = providers.associate { it.key to ProviderClient(it) }
    private val refreshStates = ConcurrentHashMap<ModelID<dev.klerkframework.webextra.auth.AuthSession>, RefreshState>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init {
        require(providers.isNotEmpty()) { "There must be at least one provider" }
        require(this.providers.size == providers.size) { "Two providers have the same key" }
        require(rbac != null || providers.all { it.roleSync == RoleSync.App }) {
            "A provider that gives roles needs the RbacPlugin"
        }
    }

    override fun mergeSpecification(previous: Specification<C, V>): Specification<C, V> {
        require(previous.plugins.any { it === users }) { "$name must be listed after ${users.name}" }
        previous.managedModels.firstOrNull {
            it.kClass == AuthOidcFlow::class || it.kClass.simpleName == "AuthOidcFlow"
        }
            ?.let { throw IllegalArgumentException("A managed model named 'AuthOidcFlow' conflicts with $name") }
        return previous.copy(
            managedModels = previous.managedModels + ManagedModel(
                AuthOidcFlow::class,
                authOidcFlowStateMachine(),
                flowViews,
            ),
        )
    }

    override suspend fun start(klerk: Klerk<C, V>) {
        this.klerk = klerk
        if (providers.values.any { it.refreshCheckInterval != null }) {
            scope.launch {
                while (isActive) {
                    delay(refreshTickInterval)
                    try {
                        runRefreshChecks()
                    } catch (e: Exception) {
                        logger.error(e) { "Checking the logins at the providers failed" }
                    }
                }
            }
        }
    }

    override fun stop() {
        scope.cancel()
    }

    private fun system(): C = klerk.specification.systemContextProvider()

    private fun now(): Instant = klerk.settings.clock.now()

    /** The buttons to show on the login page: pass them to `usersRoutes`. */
    public fun loginOptions(): List<LoginOption> = providers.values.map {
        LoginOption("Log in with ${it.label}", "${paths.login}/oidc/${it.key}")
    }

    /** Where the provider [key] sends the browser back to. */
    public fun redirectUri(key: String): String =
        users.settings.baseUrl.trimEnd('/') + paths.login + "/oidc/" + key + "/callback"

    /**
     * Starts a login with the provider [providerKey]. Set the cookie [OidcLoginStart.flowCookie] under the name
     * [FLOW_COOKIE] and send the browser to [OidcLoginStart.redirectUrl].
     */
    public suspend fun beginLogin(providerKey: String): OidcLoginStart {
        val client = clients[providerKey] ?: throw IllegalArgumentException("There is no provider '$providerKey'")
        val provider = client.provider
        val metadata = client.metadata()
        val secret = newSecret()
        val binding = newSecret()
        val verifier = CodeVerifier()
        val nonce = Nonce()
        val result = klerk.handle(
            Command(
                IssueAuthOidcFlow,
                IssueAuthOidcFlowParams(
                    provider = ProviderKey(provider.key),
                    stateHash = TokenHash(sha256Hex(secret)),
                    bindingHash = TokenHash(sha256Hex(binding)),
                    expiresAt = ExpiresAt(now() + flowValidity),
                ),
            ),
            system(),
        )
        val id = requireNotNull(result.getOrThrow().primaryModel)
        val scopes = Scope("openid").also { scope ->
            provider.scopes.forEach { scope.add(it) }
            if (provider.refreshCheckInterval != null) scope.add("offline_access")
        }
        val request = AuthenticationRequest.Builder(
            ResponseType.CODE,
            scopes,
            ClientID(provider.clientId),
            URI(redirectUri(provider.key)),
        )
            .endpointURI(metadata.authorizationEndpointURI)
            .state(State("${id.value}.$secret"))
            .nonce(nonce)
            .codeChallenge(verifier, CodeChallengeMethod.S256)
            .build()
        return OidcLoginStart(request.toURI().toString(), "$binding.${verifier.value}.${nonce.value}")
    }

    /**
     * Finishes a login that [beginLogin] started: [parameters] are the query parameters of the request the provider
     * sent the browser back with, and [flowCookie] the value of the cookie [FLOW_COOKIE]. A login can only be finished
     * once.
     */
    public suspend fun completeLogin(
        providerKey: String,
        parameters: Map<String, String>,
        flowCookie: String?,
    ): OidcLoginResult {
        val client = clients[providerKey] ?: return reject(OidcRejection.InvalidRequest, "unknown provider")
        val provider = client.provider
        val cookie = flowCookie?.split('.')?.takeIf { it.size == 3 }
            ?: return reject(OidcRejection.InvalidRequest, "no flow cookie")
        val (binding, verifier, nonce) = cookie
        val state = parameters["state"] ?: return reject(OidcRejection.InvalidRequest, "no state")
        if (!consumeFlow(provider, state, binding)) return reject(OidcRejection.InvalidRequest, "state not accepted")
        parameters["error"]?.let {
            return reject(OidcRejection.ProviderError, "$it: ${parameters["error_description"]}")
        }
        val code = parameters["code"] ?: return reject(OidcRejection.InvalidRequest, "no code")

        val claims: IDTokenClaimsSet
        val refreshToken: String?
        try {
            val tokens = client.exchange(code, verifier, URI(redirectUri(provider.key)))
            refreshToken = tokens.refreshToken
            claims = client.validate(tokens.idToken, Nonce(nonce))
        } catch (e: ProviderException) {
            return reject(OidcRejection.ProviderError, e.message ?: "")
        } catch (e: BadJOSEException) {
            return reject(OidcRejection.InvalidToken, e.message ?: "")
        } catch (e: com.nimbusds.jose.JOSEException) {
            return reject(OidcRejection.InvalidToken, e.message ?: "")
        }
        for ((claim, expected) in provider.requiredClaims) {
            if (claims.getClaim(claim)?.toString()?.lowercase() != expected.lowercase()) {
                return reject(OidcRejection.InvalidToken, "the claim $claim was not '$expected'")
            }
        }
        val subject = claims.getClaim(provider.subjectClaim)?.toString()?.takeIf { it.isNotBlank() }
            ?: return reject(OidcRejection.InvalidToken, "no ${provider.subjectClaim} claim")

        val roles = try {
            mappedRoles(provider, claims)
        } catch (e: GroupsOverageException) {
            return reject(OidcRejection.GroupsOverage, "user ${provider.key}:$subject has too many groups")
        }
        if (provider.roleSync == RoleSync.Authoritative && roles.isEmpty()) {
            return reject(OidcRejection.MissingRole, "user ${provider.key}:$subject has no mapped role")
        }

        val email = (claims.getStringClaim("email") ?: claims.getStringClaim("preferred_username"))?.trim()
        val name = claims.getStringClaim("name")?.trim()?.takeIf { it.isNotEmpty() }
        val user = when (val resolved = resolveUser(provider, subject, email, name, roles.isNotEmpty())) {
            is Resolved.Rejected -> return reject(resolved.reason, "user ${provider.key}:$subject: ${resolved.detail}")
            is Resolved.User -> resolved.id
        }
        if (name != null) users.renameUser(user, name)
        rbac?.takeIf { provider.roleSync != RoleSync.App }?.applyProviderRoles(
            user,
            provider.key,
            roles,
            provider.roleSync,
            provider.allowSuperadminMapping,
        )
        return OidcLoginResult.LoggedIn(user, provider, claims.getStringClaim("sid"), refreshToken)
    }

    /**
     * Gives the browser a session for a login that [completeLogin] accepted, and returns it. The session lasts for
     * [OidcProvider.sessionLifetime].
     */
    public suspend fun finishLogin(call: ApplicationCall, login: OidcLoginResult.LoggedIn): IssuedSession {
        val provider = login.provider
        val session = users.logIn(
            call,
            login.user,
            lifetime = provider.sessionLifetime,
            provider = provider.key,
            providerSessionId = login.providerSessionId,
        )
        val interval = provider.refreshCheckInterval
        if (interval != null) {
            if (login.refreshToken == null) {
                logger.warn { "The provider ${provider.key} gave no refresh token, so the session is not checked" }
            } else {
                refreshStates[session.id] = RefreshState(provider, login.refreshToken, now() + interval)
            }
        }
        return session
    }

    /**
     * Ends the sessions that the provider [providerKey] gave the login session [providerSessionId], when the user logs
     * out there. [issuer] is the `iss` parameter of the request, if there was one.
     *
     * @return false if the request is not acceptable
     */
    public suspend fun frontChannelLogout(providerKey: String, providerSessionId: String?, issuer: String?): Boolean {
        val provider = providers[providerKey]?.takeIf { it.frontChannelLogout } ?: return false
        if (providerSessionId.isNullOrBlank() || (issuer != null && issuer != provider.issuer)) return false
        users.revokeProviderSessions(provider.key, providerSessionId)
        return true
    }

    internal suspend fun runRefreshChecks() {
        val current = now()
        for ((sessionId, state) in refreshStates.entries.toList()) {
            if (state.dueAt > current) continue
            val active = klerk.read(system()) {
                getOrNull(sessionId)?.isIn(dev.klerkframework.webextra.auth.AuthSessionStates.Active) == true
            }
            if (!active) {
                refreshStates.remove(sessionId)
                continue
            }
            val client = clients.getValue(state.provider.key)
            when (val outcome = client.refresh(state.refreshToken)) {
                is RefreshOutcome.Refreshed -> {
                    val next = RefreshState(
                        state.provider,
                        outcome.refreshToken ?: state.refreshToken,
                        current + state.provider.refreshCheckInterval!!,
                    )
                    refreshStates[sessionId] = next
                }
                RefreshOutcome.Refused -> {
                    logger.info {
                        "The provider ${state.provider.key} no longer lets a user log in; ending the session"
                    }
                    refreshStates.remove(sessionId)
                    users.revokeSession(sessionId)
                }
                RefreshOutcome.Unavailable -> Unit
            }
        }
    }

    private fun reject(reason: OidcRejection, detail: String): OidcLoginResult.Rejected {
        logger.warn { "Login with OpenID Connect rejected ($reason): $detail" }
        return OidcLoginResult.Rejected(reason)
    }

    private suspend fun consumeFlow(provider: OidcProvider, state: String, binding: String): Boolean {
        val separator = state.indexOf('.')
        if (separator <= 0) return false
        val id = state.substring(0, separator).toIntOrNull() ?: return false
        val secret = state.substring(separator + 1)
        val flowId = ModelID<AuthOidcFlow>(id)
        val flow = klerk.read(system()) { getOrNull(flowId) } ?: return false
        val props = flow.props
        val acceptable = flow.isIn(AuthOidcFlowStates.Issued) &&
            props.provider.value == provider.key &&
            props.expiresAt.value > now() &&
            constantTimeEquals(props.stateHash.value, sha256Hex(secret)) &&
            constantTimeEquals(props.bindingHash.value, sha256Hex(binding))
        if (!acceptable) return false
        return klerk.handle(Command(UseAuthOidcFlow, flowId), system()) is CommandResult.Success
    }

    private fun mappedRoles(provider: OidcProvider, claims: IDTokenClaimsSet): Set<String> {
        val claim = provider.roleClaim ?: return emptySet()
        val names = claims.getClaim("_claim_names")
        if (claim == "groups" && names is Map<*, *> && names.containsKey("groups")) throw GroupsOverageException()
        val values = when (val raw = claims.getClaim(claim)) {
            null -> emptyList()
            is String -> listOf(raw)
            is Collection<*> -> raw.filterIsInstance<String>()
            else -> emptyList()
        }
        return values.mapNotNull { provider.roleMapping[it] }.toSet()
    }

    private sealed class Resolved {
        class User(val id: ModelID<dev.klerkframework.webextra.auth.User>) : Resolved()
        class Rejected(val reason: OidcRejection, val detail: String) : Resolved()
    }

    private suspend fun resolveUser(
        provider: OidcProvider,
        subject: String,
        email: String?,
        name: String?,
        hasMappedRole: Boolean,
    ): Resolved {
        users.findUserByIdentity(provider.key, subject)?.let {
            return if (users.isActive(
                    it,
                )
            ) {
                Resolved.User(it)
            } else {
                Resolved.Rejected(OidcRejection.UserDisabled, "disabled")
            }
        }
        val existing = email?.let { users.findUserId(it) }
        if (existing != null) {
            if (provider.linkBy != LinkBy.Email) {
                return Resolved.Rejected(OidcRejection.EmailProblem, "the address belongs to another user")
            }
            if (!users.isActive(existing)) return Resolved.Rejected(OidcRejection.UserDisabled, "disabled")
            if (users.identitiesOf(existing).any { it.provider.value == provider.key }) {
                return Resolved.Rejected(OidcRejection.EmailProblem, "the user has another identity at the provider")
            }
            return if (users.linkIdentity(existing, provider.key, subject)) {
                Resolved.User(existing)
            } else {
                Resolved.Rejected(OidcRejection.InvalidRequest, "could not link")
            }
        }
        if (!provider.provisionUsers || !hasMappedRole) {
            return Resolved.Rejected(OidcRejection.NotInvited, "not linked and not provisioned")
        }
        if (email == null) return Resolved.Rejected(OidcRejection.EmailProblem, "no email address")
        val created = users.createUser(email, name ?: email.substringBefore('@'))
            ?: return Resolved.Rejected(OidcRejection.EmailProblem, "the user could not be created")
        return if (users.linkIdentity(created, provider.key, subject)) {
            Resolved.User(created)
        } else {
            Resolved.Rejected(OidcRejection.InvalidRequest, "could not link")
        }
    }

    private class GroupsOverageException : Exception()

    private class ProviderException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private class RefreshState(val provider: OidcProvider, val refreshToken: String, val dueAt: Instant)

    private sealed class RefreshOutcome {
        class Refreshed(val refreshToken: String?) : RefreshOutcome()
        object Refused : RefreshOutcome()
        object Unavailable : RefreshOutcome()
    }

    private class Tokens(val idToken: com.nimbusds.jwt.JWT, val refreshToken: String?)

    private class CachedMetadata(val metadata: OIDCProviderMetadata, val fetchedAt: Long)

    private inner class ProviderClient(val provider: OidcProvider) {

        @Volatile
        private var cached: CachedMetadata? = null

        @Volatile
        private var validator: IDTokenValidator? = null

        suspend fun metadata(): OIDCProviderMetadata {
            val current = cached
            if (current != null &&
                System.currentTimeMillis() - current.fetchedAt < metadataValidity.inWholeMilliseconds
            ) {
                return current.metadata
            }
            val metadata = try {
                withContext(Dispatchers.IO) {
                    OIDCProviderMetadata.resolve(Issuer(provider.issuer), HTTP_CONNECT_TIMEOUT_MS, HTTP_READ_TIMEOUT_MS)
                }
            } catch (e: Exception) {
                throw ProviderException("Could not read the configuration of ${provider.issuer}: ${e.message}", e)
            }
            cached = CachedMetadata(metadata, System.currentTimeMillis())
            validator = IDTokenValidator(
                metadata.issuer,
                ClientID(provider.clientId),
                JWSAlgorithm.parse(provider.signingAlgorithm),
                metadata.jwkSetURI.toURL(),
                DefaultResourceRetriever(HTTP_CONNECT_TIMEOUT_MS, HTTP_READ_TIMEOUT_MS, JWKS_SIZE_LIMIT),
            )
            return metadata
        }

        private fun clientAuthentication(metadata: OIDCProviderMetadata): ClientAuthentication {
            val id = ClientID(provider.clientId)
            val secret = Secret(provider.clientSecret)
            val methods = metadata.tokenEndpointAuthMethods
            return if (methods != null &&
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC !in methods &&
                ClientAuthenticationMethod.CLIENT_SECRET_POST in methods
            ) {
                ClientSecretPost(id, secret)
            } else {
                ClientSecretBasic(id, secret)
            }
        }

        suspend fun exchange(code: String, verifier: String, redirect: URI): Tokens {
            val metadata = metadata()
            val request = TokenRequest(
                metadata.tokenEndpointURI,
                clientAuthentication(metadata),
                AuthorizationCodeGrant(AuthorizationCode(code), redirect, CodeVerifier(verifier)),
            )
            val response = try {
                withContext(Dispatchers.IO) {
                    val http = request.toHTTPRequest()
                    http.connectTimeout = HTTP_CONNECT_TIMEOUT_MS
                    http.readTimeout = HTTP_READ_TIMEOUT_MS
                    OIDCTokenResponseParser.parse(http.send())
                }
            } catch (e: Exception) {
                throw ProviderException("The token request failed: ${e.message}", e)
            }
            if (!response.indicatesSuccess()) {
                val error = response.toErrorResponse().errorObject
                throw ProviderException("The token request was refused: ${error.code} ${error.description}")
            }
            val tokens = (response.toSuccessResponse() as OIDCTokenResponse).getOIDCTokens()
            val idToken = tokens.idToken ?: throw ProviderException("The answer has no ID token")
            return Tokens(idToken, tokens.refreshToken?.value)
        }

        suspend fun validate(idToken: com.nimbusds.jwt.JWT, nonce: Nonce): IDTokenClaimsSet {
            metadata()
            return withContext(Dispatchers.IO) { requireNotNull(validator).validate(idToken, nonce) }
        }

        suspend fun refresh(refreshToken: String): RefreshOutcome {
            val metadata = try {
                metadata()
            } catch (e: ProviderException) {
                return RefreshOutcome.Unavailable
            }
            val request = TokenRequest(
                metadata.tokenEndpointURI,
                clientAuthentication(metadata),
                RefreshTokenGrant(RefreshToken(refreshToken)),
            )
            val response = try {
                withContext(Dispatchers.IO) {
                    val http = request.toHTTPRequest()
                    http.connectTimeout = HTTP_CONNECT_TIMEOUT_MS
                    http.readTimeout = HTTP_READ_TIMEOUT_MS
                    TokenResponse.parse(http.send())
                }
            } catch (e: Exception) {
                logger.warn { "Could not refresh a token at ${provider.key}: ${e.message}" }
                return RefreshOutcome.Unavailable
            }
            if (response.indicatesSuccess()) {
                return RefreshOutcome.Refreshed(response.toSuccessResponse().tokens.refreshToken?.value)
            }
            val code = response.toErrorResponse().errorObject.code
            return if (code in refusals) RefreshOutcome.Refused else RefreshOutcome.Unavailable
        }
    }

    public companion object {
        /** The name of the cookie that [OidcLoginStart.flowCookie] is set as. */
        public const val FLOW_COOKIE: String = "oidc-flow"

        private val refusals = setOf("invalid_grant", "interaction_required", "login_required", "consent_required")
    }
}

private val secureRandom = SecureRandom()

private fun newSecret(): String {
    val bytes = ByteArray(32)
    secureRandom.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}

private fun sha256Hex(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }

private fun constantTimeEquals(a: String, b: String): Boolean = MessageDigest.isEqual(a.toByteArray(), b.toByteArray())
