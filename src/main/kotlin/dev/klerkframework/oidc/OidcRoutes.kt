package dev.klerkframework.oidc

import dev.klerkframework.klerk.KlerkContext
import dev.klerkframework.web.WebSupport
import dev.klerkframework.webextra.auth.UsersPlugin
import dev.klerkframework.webextra.auth.clearCookie
import dev.klerkframework.webextra.auth.hostCookieName
import dev.klerkframework.webextra.auth.setCookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.html.a
import kotlinx.html.h1
import kotlinx.html.p
import mu.KotlinLogging
import kotlin.time.Duration.Companion.minutes

private val logger = KotlinLogging.logger {}

/**
 * The pages for logging in with OpenID Connect, under the login path of [OidcPlugin.paths]:
 *
 * * `GET /login/oidc/{provider}`: sends the browser to the provider.
 * * `GET /login/oidc/{provider}/callback`: where the provider sends the browser back. Logs the user in.
 * * `GET /login/oidc/{provider}/frontchannel-logout`: only for providers with [OidcProvider.frontChannelLogout].
 *
 * Show the way in with `usersRoutes(support, users, loginOptions = oidc.loginOptions())`.
 */
public fun <C : KlerkContext, V> Route.oidcRoutes(
    support: WebSupport<C, V>,
    users: UsersPlugin<C, V>,
    oidc: OidcPlugin<C, V>,
) {
    val paths = oidc.paths
    val cookieName = hostCookieName(OidcPlugin.FLOW_COOKIE)

    get("${paths.login}/oidc/{provider}") {
        val key = call.parameters["provider"].orEmpty()
        if (key !in oidc.providers) return@get call.respond(HttpStatusCode.NotFound)
        val start = try {
            oidc.beginLogin(key)
        } catch (e: Exception) {
            logger.error(e) { "Could not start a login with $key" }
            return@get loginFailed(support, paths.login, OidcRejection.ProviderError, call)
        }
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.setCookie(cookieName, start.flowCookie, 10.minutes)
        call.respondRedirect(start.redirectUrl)
    }

    get("${paths.login}/oidc/{provider}/callback") {
        val key = call.parameters["provider"].orEmpty()
        if (key !in oidc.providers) return@get call.respond(HttpStatusCode.NotFound)
        call.response.header(HttpHeaders.CacheControl, "no-store")
        val parameters = call.request.queryParameters.entries().associate { it.key to it.value.first() }
        val cookie = call.request.cookies[cookieName]
        call.clearCookie(cookieName)
        when (val result = oidc.completeLogin(key, parameters, cookie)) {
            is OidcLoginResult.Rejected -> loginFailed(support, paths.login, result.reason, call)
            is OidcLoginResult.LoggedIn -> {
                oidc.finishLogin(call, result)
                call.respondRedirect(paths.afterLogin)
            }
        }
    }

    get("${paths.login}/oidc/{provider}/frontchannel-logout") {
        val key = call.parameters["provider"].orEmpty()
        val accepted = oidc.frontChannelLogout(
            key,
            call.request.queryParameters["sid"],
            call.request.queryParameters["iss"],
        )
        call.response.header(HttpHeaders.CacheControl, "no-store")
        if (accepted) {
            call.respondText("OK")
        } else {
            call.respond(HttpStatusCode.BadRequest)
        }
    }
}

private suspend fun <C : KlerkContext, V> loginFailed(
    support: WebSupport<C, V>,
    loginPath: String,
    reason: OidcRejection,
    call: io.ktor.server.application.ApplicationCall,
) {
    support.respondPage(call, "Log in", status = HttpStatusCode.Forbidden) {
        h1 { +"Login failed" }
        p { +reason.message }
        p { a(loginPath) { +"Back to the login page" } }
    }
}
