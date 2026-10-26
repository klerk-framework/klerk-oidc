package dev.klerkframework.oidc

import dev.klerkframework.klerk.EventVisibility
import dev.klerkframework.klerk.InstanceEventNoParameters
import dev.klerkframework.klerk.KlerkContext
import dev.klerkframework.klerk.LifecycleArgs
import dev.klerkframework.klerk.VoidEventArgs
import dev.klerkframework.klerk.VoidEventWithParameters
import dev.klerkframework.klerk.statemachine.StateMachine
import dev.klerkframework.klerk.statemachine.stateMachine
import dev.klerkframework.klerk.view.ModelViews
import dev.klerkframework.webextra.auth.ExpiresAt
import dev.klerkframework.webextra.auth.ProviderKey
import dev.klerkframework.webextra.auth.TokenHash
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * A login that has been started at an identity provider and not finished. Managed by [OidcPlugin]; only hashes are
 * stored. It can be used once, which is what stops a callback from being replayed.
 */
public data class AuthOidcFlow(
    val provider: ProviderKey,
    /** The hash of the secret in the `state` parameter. */
    val stateHash: TokenHash,
    /** The hash of the secret in the cookie of the browser that started the login. */
    val bindingHash: TokenHash,
    val expiresAt: ExpiresAt,
)

/** The life of an [AuthOidcFlow]. */
public enum class AuthOidcFlowStates {
    /** The login can be finished. */
    Issued,

    /** The provider has sent the user back. It cannot be used again. */
    Used,

    /** The user did not come back in time. */
    Expired,
}

/** Issued by [OidcPlugin] when a login starts. Not meant to be rendered. */
public object IssueAuthOidcFlow :
    VoidEventWithParameters<AuthOidcFlow, IssueAuthOidcFlowParams>(EventVisibility.Application)

/** Issued by [OidcPlugin] when the provider sends the user back. Not meant to be rendered. */
public object UseAuthOidcFlow : InstanceEventNoParameters<AuthOidcFlow>(EventVisibility.Application)

/** Parameters of [IssueAuthOidcFlow]. */
public data class IssueAuthOidcFlowParams(
    val provider: ProviderKey,
    val stateHash: TokenHash,
    val bindingHash: TokenHash,
    val expiresAt: ExpiresAt,
)

/** The views of [AuthOidcFlow]. */
public class AuthOidcFlowViews<C : KlerkContext> : ModelViews<AuthOidcFlow, C>()

internal fun <C : KlerkContext, V> authOidcFlowStateMachine(): StateMachine<AuthOidcFlow, AuthOidcFlowStates, C, V> =
    stateMachine {
        event(IssueAuthOidcFlow) {}
        event(UseAuthOidcFlow) {}

        voidState {
            onEvent(IssueAuthOidcFlow) { createModel(AuthOidcFlowStates.Issued, ::newAuthOidcFlow) }
        }

        state(AuthOidcFlowStates.Issued) {
            onEvent(UseAuthOidcFlow) { transitionTo(AuthOidcFlowStates.Used) }
            atTime(::authOidcFlowExpiry) { transitionTo(AuthOidcFlowStates.Expired) }
        }

        state(AuthOidcFlowStates.Used) {
            after(1.days) { delete() }
        }

        state(AuthOidcFlowStates.Expired) {
            after(1.days) { delete() }
        }
    }

private fun <C : KlerkContext, V> newAuthOidcFlow(
    args: VoidEventArgs<AuthOidcFlow, IssueAuthOidcFlowParams, C, V>,
): AuthOidcFlow {
    val params = args.command.params
    return AuthOidcFlow(params.provider, params.stateHash, params.bindingHash, params.expiresAt)
}

private fun <C : KlerkContext, V> authOidcFlowExpiry(args: LifecycleArgs<AuthOidcFlow, C, V>): Instant =
    args.model.props.expiresAt.value
