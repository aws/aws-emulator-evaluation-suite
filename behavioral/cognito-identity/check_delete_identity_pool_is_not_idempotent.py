"""delete-identity-pool-is-not-idempotent."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-pool-is-not-idempotent"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_pool(ci, pool_id):
    """Teardown that tolerates a pool the check itself already deleted."""
    from botocore.exceptions import ClientError

    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"env": "test", "owner": "fidelity-check"},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(client, pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive guard: deleting an already-deleted pool must 404, not silently succeed."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    ev.delete_identity_pool(IdentityPoolId=pool_id)
    expected = f"IdentityPool '{pool_id}' not found."
    err, message = _error(lambda: ev.delete_identity_pool(IdentityPoolId=pool_id))
    assert err == "ResourceNotFoundException", (
        f"second DeleteIdentityPool must fail with ResourceNotFoundException, got {err}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    err_update, message = _error(
        lambda: ev.update_identity_pool(
            IdentityPoolId=pool_id,
            IdentityPoolName="sim2real_behav_ghost_pool",
            AllowUnauthenticatedIdentities=True,
        )
    )
    assert err_update == "ResourceNotFoundException", (
        f"UpdateIdentityPool on a deleted pool must fail with ResourceNotFoundException, got {err_update}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    err_describe, message = _error(lambda: ev.describe_identity_pool(IdentityPoolId=pool_id))
    assert err_describe == "ResourceNotFoundException", (
        f"independent DescribeIdentityPool read on the deleted pool must fail with "
        f"ResourceNotFoundException, got {err_describe}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
