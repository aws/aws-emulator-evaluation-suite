"""unlink-identity-unknown-identity-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-unknown-identity-rejected"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because an over-permissive target accepting a call real AWS refuses
    is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ci, ctx, allow_unauth=True, name_prefix="pool-unlinkid-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = ctx.unique_name(f"sim2real-behav-{name_prefix}").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity on a never-issued IdentityId answers ResourceNotFoundException "Identity
    '<id>' not found.", while on a real unauthenticated identity it answers NotAuthorizedException
    "Cannot unlink unauthenticated user." and leaves Logins empty."""
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(
        ci, ctx, allow_unauth=True, IdentityPoolTags={"sim2real": CHECK}
    )
    real_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    # Cleanups run LIFO, so the identity is deleted before the pool that owns it.
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[real_id]))
    region_prefix = real_id.split(":")[0]
    ghost_id = f"{region_prefix}:11111111-1111-1111-1111-111111111111"

    logins = {"graph.facebook.com": "sim2real-behav-bogus-token"}
    logins_to_remove = ["graph.facebook.com"]

    code, message = _error(
        lambda: ci.unlink_identity(
            IdentityId=ghost_id, Logins=logins, LoginsToRemove=logins_to_remove
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected UnlinkIdentity on an unknown identity to raise "
        f"ResourceNotFoundException, got {code}"
    )
    assert message == f"Identity '{ghost_id}' not found.", message

    # Positive control: the identical call against the identity the pool issued answers a
    # different error, so the ResourceNotFoundException above is specific to the unknown id.
    control_code, control_message = _error(
        lambda: ci.unlink_identity(
            IdentityId=real_id, Logins=logins, LoginsToRemove=logins_to_remove
        )
    )
    assert control_code == "NotAuthorizedException", (
        f"expected the identical call against the real, issued identity to fail "
        f"authentication (NotAuthorizedException) rather than ResourceNotFoundException, "
        f"got {control_code!r} -- otherwise the rejection above cannot be attributed to "
        f"the identity being unknown"
    )
    assert control_message == "Cannot unlink unauthenticated user.", control_message

    # Terminal read is independent of both rejected calls: DescribeIdentity, not UnlinkIdentity.
    # Neither rejection may have left a mark on the real identity's logins.
    after = ci.describe_identity(IdentityId=real_id)
    assert after.get("Logins", []) == [], (
        f"the rejected UnlinkIdentity calls must not change the real identity's logins, "
        f"got {after.get('Logins')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
