"""developer-provider-must-be-configured-on-pool."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "developer-provider-must-be-configured-on-pool"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with a Logins key other than the pool's
    DeveloperProviderName is refused with InvalidParameterException and the exact message and links
    nothing, while the pool's own provider still resolves the control user to its identity."""
    ev = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-devprov-")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName=dev_provider)

    # Positive control: the pool's own developer provider works.
    dev_user = ctx.unique_name("sim2real-devuser-")
    control_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    assert control_identity_id.startswith(f"{ctx.region}:"), (
        f"expected a real identity id from the positive control, got {control_identity_id!r}"
    )

    # Break exactly one thing: Logins is present, but keyed by a provider name the pool
    # was never configured with.
    other_user = ctx.unique_name("sim2real-devuser-")
    err = _client_error(
        lambda: ev.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            Logins={"login.someone.else": other_user},
        )
    )
    assert err == ("InvalidParameterException", "This identity pool does not support the specified developer provider."), (
        f"expected InvalidParameterException for a developer provider not configured on the pool, got {err!r}"
    )

    # Effect absent: the mis-keyed attempt minted nothing for other_user -- a
    # correctly-keyed request for that same user identifier gets a genuinely fresh
    # identity, distinct from the control identity.
    resolved_other = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: other_user}
    )["IdentityId"]
    assert resolved_other != control_identity_id, (
        "the rejected attempt must not have pre-linked other_user to the control identity"
    )

    # The pool's real developer provider is unaffected by the rejected attempt.
    resolved_control = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    assert resolved_control == control_identity_id, (
        f"expected the control identity to still resolve to {control_identity_id!r}, got {resolved_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
