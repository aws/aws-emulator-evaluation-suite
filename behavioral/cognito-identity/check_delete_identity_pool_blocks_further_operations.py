"""delete-identity-pool-blocks-further-operations."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-pool-blocks-further-operations"
GROUP = "lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteIdentityPool, DescribeIdentityPool, GetId, GetIdentityPoolRoles and
    SetIdentityPoolRoles each answer ResourceNotFoundException "IdentityPool '<id>' not found."; the
    reads succeed on the live pool first, so the refusal comes from the delete."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_if_present(ci, pool_id))

    # Positive control: every op probed post-delete must succeed against the live pool.
    live_describe = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert live_describe["IdentityPoolId"] == pool_id, live_describe
    live_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert live_id
    live_roles = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert live_roles["IdentityPoolId"] == pool_id, live_roles

    ci.delete_identity_pool(IdentityPoolId=pool_id)

    probes = {
        "describe_identity_pool": lambda: ci.describe_identity_pool(IdentityPoolId=pool_id),
        "get_id": lambda: ci.get_id(IdentityPoolId=pool_id),
        "get_identity_pool_roles": lambda: ci.get_identity_pool_roles(IdentityPoolId=pool_id),
        # A write, not just a read: the pool must be unusable, not merely unreadable.
        "set_identity_pool_roles": lambda: ci.set_identity_pool_roles(
            IdentityPoolId=pool_id, Roles={}
        ),
    }
    expected = ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    for op, fn in probes.items():
        got = _error(fn)
        assert got == expected, f"{op}: expected {expected!r}, got {got!r}"


def _delete_if_present(ci: Any, pool_id: str) -> None:
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn: Any) -> tuple[str, str]:
    """Call fn() expecting a refusal; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
