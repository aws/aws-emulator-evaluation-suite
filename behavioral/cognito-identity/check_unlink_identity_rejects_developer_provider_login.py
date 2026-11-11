"""unlink-identity-rejects-developer-provider-login."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-rejects-developer-provider-login"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised. An unexpected
    SUCCESS raises -- an emulator ACCEPTING a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK}, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity with a developer-provider login is refused with InvalidParameterException
    "Please provide a valid public provider" and the login stays linked; UnlinkDeveloperIdentity
    removes it, so the same user then gets a new identity."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName="login.myapp")
    user_id = ctx.unique_name("sim2real-behav-devuser-")
    identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": user_id}
    )["IdentityId"]
    err, message = _error(
        lambda: ev.unlink_identity(
            IdentityId=identity_id,
            Logins={"login.myapp": user_id},
            LoginsToRemove=["login.myapp"],
        )
    )
    assert err == "InvalidParameterException", (
        f"UnlinkIdentity must not silently strip a developer-provider login supplied without a "
        f"verifiable token, got {err}"
    )
    assert message == "Please provide a valid public provider", message
    lookup = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_id, MaxResults=10
    )
    assert lookup["IdentityId"] == identity_id, "rejected UnlinkIdentity must not mutate the identity"

    # Positive control: the correct API (UnlinkDeveloperIdentity, not UnlinkIdentity) does remove
    # this exact developer-provider login, and removal is real -- the same developer user
    # identifier now mints a genuinely different identity.
    ev.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName="login.myapp",
        DeveloperUserIdentifier=user_id,
    )
    relinked_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": user_id}
    )["IdentityId"]
    assert relinked_id != identity_id, (
        f"UnlinkDeveloperIdentity must actually detach the login, but re-authenticating "
        f"{user_id!r} still resolved to the original identity {identity_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
