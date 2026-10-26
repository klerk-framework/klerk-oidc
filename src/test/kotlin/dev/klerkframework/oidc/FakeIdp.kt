package dev.klerkframework.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.util.Base64
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList

/** An OpenID Connect provider on a local port: discovery, keys and a token endpoint that says what the test tells it. */
class FakeIdp(val clientId: String = "client-id", val clientSecret: String = "client-secret") : AutoCloseable {

    private val key: RSAKey = RSAKeyGenerator(2048).keyID("k1").generate()
    private val strangerKey: RSAKey = RSAKeyGenerator(2048).keyID("k1").generate()

    /** What the token endpoint answers a code with. */
    @Volatile
    var idToken: String = ""

    @Volatile
    var refreshToken: String? = "refresh-1"

    /** What the token endpoint answers a refresh token with: null means success, otherwise the OAuth error code. */
    @Volatile
    var refreshError: String? = null

    val codeRequests = CopyOnWriteArrayList<Map<String, String>>()
    val refreshRequests = CopyOnWriteArrayList<Map<String, String>>()

    private val server = embeddedServer(Netty, port = 0) {
        routing {
            get("/.well-known/openid-configuration") {
                call.respondText(
                    """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token",
                    |"jwks_uri":"$issuer/jwks","id_token_signing_alg_values_supported":["RS256"],
                    |"subject_types_supported":["public"],"response_types_supported":["code"],
                    |"token_endpoint_auth_methods_supported":["client_secret_basic"]}
                    """.trimMargin(),
                    ContentType.Application.Json,
                )
            }
            get("/jwks") {
                call.respondText(JWKSet(key.toPublicJWK()).toString(), ContentType.Application.Json)
            }
            post("/token") {
                val expected = "Basic " + Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray())
                if (call.request.headers[HttpHeaders.Authorization] != expected) {
                    return@post call.respondText(
                        """{"error":"invalid_client"}""",
                        ContentType.Application.Json,
                        HttpStatusCode.Unauthorized,
                    )
                }
                val form = call.receiveParameters().entries().associate { it.key to it.value.first() }
                if (form["grant_type"] == "refresh_token") {
                    refreshRequests.add(form)
                    val error = refreshError
                    return@post if (error != null) {
                        call.respondText(
                            """{"error":"$error"}""",
                            ContentType.Application.Json,
                            HttpStatusCode.BadRequest,
                        )
                    } else {
                        call.respondText(
                            """{"access_token":"at2","token_type":"Bearer","refresh_token":"refresh-2"}""",
                            ContentType.Application.Json,
                        )
                    }
                }
                codeRequests.add(form)
                val refresh = refreshToken?.let { ""","refresh_token":"$it"""" }.orEmpty()
                call.respondText(
                    """{"access_token":"at","token_type":"Bearer","id_token":"$idToken"$refresh}""",
                    ContentType.Application.Json,
                )
            }
        }
    }.also { it.start(wait = false) }

    val port: Int = runBlocking { server.engine.resolvedConnectors().first().port }

    val issuer: String = "http://localhost:$port"

    /**
     * An ID token for [nonce] with [claims] added to the standard ones. [issuer], [audience] and [expiresInSeconds]
     * can be wrong on purpose, and [signedByStranger] signs with a key that is not in the key set.
     */
    fun issue(
        nonce: String?,
        claims: Map<String, Any?> = emptyMap(),
        issuer: String = this.issuer,
        audience: String = clientId,
        expiresInSeconds: Long = 300,
        signedByStranger: Boolean = false,
    ): String {
        val builder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + expiresInSeconds * 1000))
        nonce?.let { builder.claim("nonce", it) }
        claims.forEach { (name, value) -> builder.claim(name, value) }
        val signing = if (signedByStranger) strangerKey else key
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), builder.build())
        jwt.sign(RSASSASigner(signing))
        return jwt.serialize()
    }

    override fun close() {
        server.stop(100, 500)
    }
}
