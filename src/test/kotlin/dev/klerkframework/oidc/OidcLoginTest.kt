package dev.klerkframework.oidc

import dev.klerkframework.klerk.command.Command
import dev.klerkframework.web.WebSupport
import dev.klerkframework.webextra.auth.AssignAuthRole
import dev.klerkframework.webextra.auth.AssignAuthRoleParams
import dev.klerkframework.webextra.auth.DisableUser
import dev.klerkframework.webextra.auth.RoleSync
import dev.klerkframework.webextra.auth.browserContext
import dev.klerkframework.webextra.auth.usersRoutes
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.setCookie
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/** A browser: remembers cookies and does not follow redirects. */
private class Browser(private val client: HttpClient) {
    val cookies = mutableMapOf<String, String>()

    suspend fun get(path: String): HttpResponse = client.get(path) {
        if (cookies.isNotEmpty()) {
            header(
                HttpHeaders.Cookie,
                cookies.entries.joinToString("; ") {
                    "${it.key}=${it.value}"
                },
            )
        }
    }.also { response ->
        response.setCookie().forEach {
            if (it.value.isEmpty() || it.maxAge == 0) cookies.remove(it.name) else cookies[it.name] = it.value
        }
    }
}

private class Started(val state: String, val nonce: String, val location: Url)

class OidcLoginTest {

    init {
        System.setProperty("DEVELOPMENT_MODE", "true")
    }

    private fun base(idp: FakeIdp) = OidcProvider(
        key = "test",
        issuer = idp.issuer,
        clientId = idp.clientId,
        clientSecret = idp.clientSecret,
        label = "Test",
        subjectClaim = "oid",
        roleClaim = "roles",
    )

    private fun withApp(
        configure: (OidcProvider) -> OidcProvider = { it },
        emailLogin: Boolean = false,
        withRbac: Boolean = true,
        block: suspend ApplicationTestBuilder.(TestApp, FakeIdp, Browser) -> Unit,
    ) = runBlocking {
        FakeIdp().use { idp ->
            val app = TestApp(listOf(configure(base(idp))), emailLogin, withRbac)
            app.start()
            testApplication {
                val support = WebSupport(app.klerk, { call, _ -> app.users.browserContext(call) })
                application {
                    routing {
                        usersRoutes(support, app.users, loginOptions = app.oidc.loginOptions())
                        oidcRoutes(support, app.users, app.oidc)
                        get("/whoami") {
                            call.respondText("user=${app.users.browserContext(call).actor.id}")
                        }
                    }
                }
                block(app, idp, Browser(createClient { followRedirects = false }))
            }
            app.klerk.meta.stop()
        }
    }

    private suspend fun Browser.start(): Started {
        val response = get("/login/oidc/test")
        assertEquals(HttpStatusCode.Found, response.status)
        val location = Url(response.headers[HttpHeaders.Location]!!)
        return Started(location.parameters["state"]!!, location.parameters["nonce"]!!, location)
    }

    private suspend fun Browser.whoami(): String = get("/whoami").bodyAsText()

    private fun claims(oid: String = "oid-1", vararg more: Pair<String, Any?>): Map<String, Any?> =
        mapOf("oid" to oid, "sub" to "pairwise-$oid", "email" to "anna@example.com", "name" to "Anna A") + more

    /** Logs in as the provider says and returns the response of the callback. */
    private suspend fun Browser.login(
        idp: FakeIdp,
        claims: Map<String, Any?> = claims(),
        issue: (nonce: String, claims: Map<String, Any?>) -> String = { nonce, c -> idp.issue(nonce, c) },
    ): HttpResponse {
        val started = start()
        idp.idToken = issue(started.nonce, claims)
        return get("/login/oidc/test/callback?code=code-1&state=${started.state}")
    }

    @Test
    fun `the login page has a button, and no email form when email login is off`() = withApp { _, _, browser ->
        val page = browser.get("/login").bodyAsText()

        assertContains(page, "Log in with Test")
        assertContains(page, "/login/oidc/test")
        assertTrue("Send login link" !in page)
    }

    @Test
    fun `the browser is sent to the provider with state, nonce and a PKCE challenge`() = withApp { _, idp, browser ->
        val started = browser.start()

        assertTrue(started.location.toString().startsWith("${idp.issuer}/authorize"))
        assertEquals("code", started.location.parameters["response_type"])
        assertEquals("S256", started.location.parameters["code_challenge_method"])
        assertNotNull(started.location.parameters["code_challenge"])
        assertEquals("client-id", started.location.parameters["client_id"])
        assertEquals("http://localhost/login/oidc/test/callback", started.location.parameters["redirect_uri"])
        assertContains(started.location.parameters["scope"]!!.split(' '), "openid")
        assertNotNull(browser.cookies["oidc-flow"])
    }

    @Test
    fun `an invited user is linked by email, logs in and stays linked`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")

        val response = browser.login(idp)

        assertEquals(HttpStatusCode.Found, response.status)
        assertEquals("/", response.headers[HttpHeaders.Location])
        assertEquals("user=${anna.value}", browser.whoami())
        assertEquals(anna, app.users.findUserByIdentity("test", "oid-1"))
        assertEquals("Anna A", app.userName(anna))
        assertEquals(1, idp.codeRequests.size)
        assertNotNull(idp.codeRequests.single()["code_verifier"])

        val second = Browser(createClient { followRedirects = false })
        val again = second.login(idp, claims(oid = "oid-1", "email" to "changed@example.com"))
        assertEquals(HttpStatusCode.Found, again.status)
        assertEquals("user=${anna.value}", second.whoami())
    }

    @Test
    fun `login works without the rbac plugin`() = withApp(
        { it.copy(linkBy = LinkBy.Email, roleClaim = null) },
        withRbac = false,
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")

        assertEquals(HttpStatusCode.Found, browser.login(idp).status)

        assertEquals("user=${anna.value}", browser.whoami())
        assertEquals(anna, app.users.findUserByIdentity("test", "oid-1"))
    }

    @Test
    fun `the callback cannot be replayed`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")
        val started = browser.start()
        idp.idToken = idp.issue(started.nonce, claims())
        val callback = "/login/oidc/test/callback?code=code-1&state=${started.state}"
        val cookie = browser.cookies["oidc-flow"]!!

        assertEquals(HttpStatusCode.Found, browser.get(callback).status)

        val again = Browser(createClient { followRedirects = false })
        again.cookies["oidc-flow"] = cookie
        assertEquals(HttpStatusCode.Forbidden, again.get(callback).status)
        assertEquals("user=null", again.whoami())
    }

    @Test
    fun `a callback from another browser or with another state is refused`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")
        val started = browser.start()
        idp.idToken = idp.issue(started.nonce, claims())

        val stranger = Browser(createClient { followRedirects = false })
        assertEquals(
            HttpStatusCode.Forbidden,
            stranger.get("/login/oidc/test/callback?code=c&state=${started.state}").status,
        )
        assertEquals(
            HttpStatusCode.Forbidden,
            browser.get("/login/oidc/test/callback?code=c&state=${started.state}x").status,
        )
        assertEquals("user=null", browser.whoami())
    }

    @Test
    fun `an ID token that is not right is refused`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, _ ->
        app.users.ensureUser("anna@example.com", "Anna")
        val bad = mapOf<String, (String, Map<String, Any?>) -> String>(
            "nonce" to { _, c -> idp.issue("some other nonce", c) },
            "no nonce" to { _, c -> idp.issue(null, c) },
            "audience" to { n, c -> idp.issue(n, c, audience = "someone-else") },
            "issuer" to { n, c -> idp.issue(n, c, issuer = "https://evil.example.com") },
            "expired" to { n, c -> idp.issue(n, c, expiresInSeconds = -3600) },
            "signature" to { n, c -> idp.issue(n, c, signedByStranger = true) },
        )
        for ((what, issue) in bad) {
            val browser = Browser(createClient { followRedirects = false })
            assertEquals(HttpStatusCode.Forbidden, browser.login(idp, issue = issue).status, what)
            assertEquals("user=null", browser.whoami(), what)
        }
        assertNull(app.users.findUserByIdentity("test", "oid-1"))
    }

    @Test
    fun `an identity that nothing lets in is refused`() = withApp { app, idp, browser ->
        val response = browser.login(idp)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertContains(response.bodyAsText(), "do not have access")
        assertNull(app.users.findUserId("anna@example.com"))
    }

    @Test
    fun `an address is not enough to get in when linking by email is off`() = withApp { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")

        assertEquals(HttpStatusCode.Forbidden, browser.login(idp).status)
        assertNull(app.users.findUserByIdentity("test", "oid-1"))
    }

    @Test
    fun `a user whose address is linked to another identity of the provider is refused`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        app.users.linkIdentity(anna, "test", "oid-1")

        val response = browser.login(idp, claims(oid = "oid-2"))

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(app.users.findUserByIdentity("test", "oid-2"))
    }

    @Test
    fun `a disabled user cannot log in`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        app.users.linkIdentity(anna, "test", "oid-1")
        app.klerk.handle(Command(DisableUser, anna), app.context(dev.klerkframework.klerk.SystemIdentity)).getOrThrow()

        assertEquals(HttpStatusCode.Forbidden, browser.login(idp).status)
        assertEquals("user=null", browser.whoami())
    }

    @Test
    fun `a user with a mapped role is created at the first login, one without is not`() = withApp(
        {
            it.copy(
                provisionUsers = true,
                roleMapping = mapOf("app-reader" to "Reader"),
                roleSync = RoleSync.Authoritative,
            )
        },
    ) { app, idp, browser ->
        app.createRole("Reader")

        val without = Browser(createClient { followRedirects = false })
        assertEquals(HttpStatusCode.Forbidden, without.login(idp, claims("oid-9", "roles" to listOf("other"))).status)
        assertNull(app.users.findUserId("anna@example.com"))

        assertEquals(HttpStatusCode.Found, browser.login(idp, claims("oid-1", "roles" to listOf("app-reader"))).status)
        val anna = app.users.findUserId("anna@example.com")
        assertNotNull(anna)
        assertEquals(anna, app.users.findUserByIdentity("test", "oid-1"))
        assertEquals("user=${anna.value}", browser.whoami())
        assertEquals(setOf("Reader"), app.roleNamesOf(anna))
        assertEquals("Anna A", app.userName(anna))
    }

    @Test
    fun `an address that belongs to another user is not taken over by provisioning`() = withApp(
        { it.copy(provisionUsers = true, roleMapping = mapOf("app-reader" to "Reader")) },
    ) { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")

        val response = browser.login(idp, claims("oid-1", "roles" to listOf("app-reader")))

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(app.users.findUserByIdentity("test", "oid-1"))
    }

    @Test
    fun `authoritative roles replace the roles an administrator gave`() = withApp(
        {
            it.copy(
                linkBy = LinkBy.Email,
                roleMapping = mapOf("app-reader" to "Reader", "app-editor" to "Editor"),
                roleSync = RoleSync.Authoritative,
            )
        },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        app.createRole("Reader")
        app.createRole("Editor")
        val manual = app.createRole("Manual")
        app.klerk.handle(
            Command(AssignAuthRole, AssignAuthRoleParams(anna, manual)),
            app.context(dev.klerkframework.klerk.SystemIdentity),
        ).getOrThrow()

        assertEquals(HttpStatusCode.Found, browser.login(idp, claims("oid-1", "roles" to listOf("app-reader"))).status)
        assertEquals(setOf("Reader"), app.roleNamesOf(anna))

        val second = Browser(createClient { followRedirects = false })
        assertEquals(
            HttpStatusCode.Found,
            second.login(idp, claims("oid-1", "roles" to listOf("app-editor", "unmapped"))).status,
        )
        assertEquals(setOf("Editor"), app.roleNamesOf(anna))

        val third = Browser(createClient { followRedirects = false })
        assertEquals(HttpStatusCode.Forbidden, third.login(idp, claims("oid-1", "roles" to emptyList<String>())).status)
        assertEquals(setOf("Editor"), app.roleNamesOf(anna))
    }

    @Test
    fun `too many groups for the token is a clear failure`() = withApp(
        {
            it.copy(
                linkBy = LinkBy.Email,
                roleClaim = "groups",
                roleMapping = mapOf("g1" to "Reader"),
                roleSync = RoleSync.Authoritative,
            )
        },
    ) { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")
        val overage = claims("oid-1", "_claim_names" to mapOf("groups" to "src1"))

        val response = browser.login(idp, overage)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertContains(response.bodyAsText(), "too many groups")
    }

    @Test
    fun `a required claim must have its value`() = withApp(
        { it.copy(linkBy = LinkBy.Email, requiredClaims = mapOf("tid" to "tenant-1")) },
    ) { app, idp, browser ->
        app.users.ensureUser("anna@example.com", "Anna")

        assertEquals(HttpStatusCode.Forbidden, browser.login(idp, claims("oid-1", "tid" to "tenant-2")).status)

        val second = Browser(createClient { followRedirects = false })
        assertEquals(HttpStatusCode.Found, second.login(idp, claims("oid-1", "tid" to "Tenant-1")).status)
    }

    @Test
    fun `a session lasts for the lifetime of the provider`() = withApp(
        { it.copy(linkBy = LinkBy.Email, sessionLifetime = 2.hours) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        browser.login(idp)
        assertEquals("user=${anna.value}", browser.whoami())

        app.clock.set(app.clock.now() + 3.hours)

        assertEquals("user=null", browser.whoami())
    }

    @Test
    fun `the provider can end a session by its id`() = withApp(
        { it.copy(linkBy = LinkBy.Email, frontChannelLogout = true) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        browser.login(idp, claims("oid-1", "sid" to "sid-1"))
        assertEquals("user=${anna.value}", browser.whoami())

        assertEquals(HttpStatusCode.BadRequest, browser.get("/login/oidc/test/frontchannel-logout").status)
        assertEquals(
            HttpStatusCode.BadRequest,
            browser.get("/login/oidc/test/frontchannel-logout?sid=sid-1&iss=https://evil.example.com").status,
        )
        assertEquals("user=${anna.value}", browser.whoami())

        assertEquals(
            HttpStatusCode.OK,
            browser.get("/login/oidc/test/frontchannel-logout?sid=sid-1&iss=${idp.issuer}").status,
        )
        assertEquals("user=null", browser.whoami())
    }

    @Test
    fun `front channel logout is off unless the provider asks for it`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { _, _, browser ->
        assertEquals(HttpStatusCode.BadRequest, browser.get("/login/oidc/test/frontchannel-logout?sid=sid-1").status)
    }

    @Test
    fun `a session ends when the provider refuses to refresh, and stays when it agrees`() = withApp(
        { it.copy(linkBy = LinkBy.Email, refreshCheckInterval = 15.minutes) },
    ) { app, idp, browser ->
        val anna = app.users.ensureUser("anna@example.com", "Anna")
        val started = browser.start()
        assertContains(started.location.parameters["scope"]!!.split(' '), "offline_access")
        idp.idToken = idp.issue(started.nonce, claims())
        browser.get("/login/oidc/test/callback?code=code-1&state=${started.state}")
        assertEquals("user=${anna.value}", browser.whoami())

        app.oidc.runRefreshChecks()
        assertEquals(0, idp.refreshRequests.size)

        app.clock.set(app.clock.now() + 16.minutes)
        app.oidc.runRefreshChecks()
        assertEquals(1, idp.refreshRequests.size)
        assertEquals("refresh-1", idp.refreshRequests.single()["refresh_token"])
        assertEquals("user=${anna.value}", browser.whoami())

        idp.refreshError = "server_error"
        app.clock.set(app.clock.now() + 16.minutes)
        app.oidc.runRefreshChecks()
        assertEquals("user=${anna.value}", browser.whoami())

        idp.refreshError = "invalid_grant"
        app.clock.set(app.clock.now() + 16.minutes)
        app.oidc.runRefreshChecks()
        assertEquals("user=null", browser.whoami())
    }

    @Test
    fun `without the setting the refresh token is not asked for`() = withApp(
        { it.copy(linkBy = LinkBy.Email) },
    ) { _, _, browser ->
        val started = browser.start()

        assertTrue("offline_access" !in started.location.parameters["scope"]!!.split(' '))
    }

    @Test
    fun `an unknown provider is not found`() = withApp { _, _, browser ->
        assertEquals(HttpStatusCode.NotFound, browser.get("/login/oidc/nope").status)
        assertEquals(HttpStatusCode.NotFound, browser.get("/login/oidc/nope/callback").status)
    }

    @Test
    fun `the provider reports an error`() = withApp { _, _, browser ->
        val started = browser.start()

        val response = browser.get("/login/oidc/test/callback?error=access_denied&state=${started.state}")

        assertEquals(HttpStatusCode.Forbidden, response.status)
    }
}
