package dev.klerkframework.oidc

import dev.klerkframework.klerk.ActorIdentity
import dev.klerkframework.klerk.DefaultTranslation
import dev.klerkframework.klerk.Klerk
import dev.klerkframework.klerk.KlerkContext
import dev.klerkframework.klerk.KlerkSettings
import dev.klerkframework.klerk.ModelID
import dev.klerkframework.klerk.SpecificationBuilder
import dev.klerkframework.klerk.SystemIdentity
import dev.klerkframework.klerk.Translation
import dev.klerkframework.klerk.command.Command
import dev.klerkframework.klerk.ecosystem.BasicEmail
import dev.klerkframework.klerk.ecosystem.EmailSender
import dev.klerkframework.klerk.job.JobExecution
import dev.klerkframework.klerk.job.JobID
import dev.klerkframework.klerk.job.JobSettings
import dev.klerkframework.klerk.misc.MutableClock
import dev.klerkframework.klerk.storage.AttachedBlobStore
import dev.klerkframework.klerk.storage.RamStorage
import dev.klerkframework.klerk.view.asSequence
import dev.klerkframework.web.assets.AssetsPlugin
import dev.klerkframework.webextra.auth.AuthRole
import dev.klerkframework.webextra.auth.AuthRoleAssignment
import dev.klerkframework.webextra.auth.CreateAuthRole
import dev.klerkframework.webextra.auth.CreateAuthRoleParams
import dev.klerkframework.webextra.auth.RbacPlugin
import dev.klerkframework.webextra.auth.RoleName
import dev.klerkframework.webextra.auth.User
import dev.klerkframework.webextra.auth.UsersPlugin
import dev.klerkframework.webextra.auth.UsersSettings
import dev.klerkframework.webextra.auth.readOwnUser
import dev.klerkframework.webextra.auth.readPropertiesOfAuthModels
import kotlin.time.Instant

data class TestCtx(
    override val actor: ActorIdentity,
    override val time: Instant,
    override val eventLogExtra: String? = null,
    override val translation: Translation = DefaultTranslation,
) : KlerkContext

class NoEmailSender : EmailSender<TestCtx, Unit> {
    override val defaultFromAddress: BasicEmail.EmailAndName = BasicEmail.EmailAndName("app@example.com", "App")
    override suspend fun sendEmail(email: BasicEmail, context: TestCtx): JobID? = null
    override fun sendEmailCommand(email: BasicEmail): Command<out Any, out Any>? = null
}

class TestApp(providers: List<OidcProvider>, emailLogin: Boolean = false, withRbac: Boolean = true) {
    val clock = MutableClock(Instant.parse("2026-10-25T10:00:00Z"))

    val users = UsersPlugin(
        UsersSettings<TestCtx, Unit>(
            baseUrl = "http://localhost",
            emailSender = NoEmailSender(),
            contextFor = { actor -> context(actor) },
            emailLogin = emailLogin,
        ),
    )
    val rbac = RbacPlugin(users)
    val oidc = OidcPlugin(users, providers, rbac.takeIf { withRbac })

    val klerk: Klerk<TestCtx, Unit> = Klerk.create(
        SpecificationBuilder<TestCtx, Unit>(Unit).build {
            if (withRbac) {
                plugins(
                    AssetsPlugin(emptySet()),
                    users,
                    rbac,
                    oidc,
                )
            } else {
                plugins(AssetsPlugin(emptySet()), users, oidc)
            }
            managedModels {}
            authorization {
                readModels { positive(::readOwnUser) }
                readProperties { positive(::readPropertiesOfAuthModels) }
            }
            systemContextProvider { context(SystemIdentity) }
            eventLogRetention(afterModelDeletion = null, paramsAndExtra = null)
        },
        KlerkSettings(
            persistence = RamStorage(),
            attachedBlobStore = AttachedBlobStore.Database,
            clock = clock,
            jobs = JobSettings(execution = JobExecution.Manual),
        ),
    )

    fun context(actor: ActorIdentity): TestCtx = TestCtx(actor, clock.now())

    suspend fun start() {
        klerk.meta.start(installShutdownHook = false)
    }

    suspend fun createRole(name: String): ModelID<AuthRole> {
        klerk.handle(
            Command(CreateAuthRole, CreateAuthRoleParams(RoleName(name), emptySet())),
            context(SystemIdentity),
        ).getOrThrow()
        return roleId(name)
    }

    suspend fun roleId(name: String): ModelID<AuthRole> = klerk.read(context(SystemIdentity)) {
        rbac.roleViews.all.asSequence().first { it.props.name.value == name }.id
    }

    suspend fun roleNamesOf(user: ModelID<User>): Set<String> = klerk.read(context(SystemIdentity)) {
        referencing(AuthRoleAssignment::user, user).map { getOrNull(it.props.role)!!.props.name.value }.toSet()
    }

    suspend fun userName(user: ModelID<User>): String = klerk.read(context(SystemIdentity)) {
        get(user).props.name.value
    }
}
