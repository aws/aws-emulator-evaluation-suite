"""not-authorized-describe-and-roles-on-foreign-pool."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-authorized-describe-and-roles-on-foreign-pool"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if it raises. An unexpected SUCCESS
    raises, because a target that fabricates success for a pool it never created is the strongest possible
    signal."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    resp = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool and GetIdentityPoolRoles on a well-formed but never-created
    IdentityPoolId answer ResourceNotFoundException with the exact message, while both succeed on a
    pool the check creates."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx)

    owner_described = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert owner_described["IdentityPoolId"] == pool_id, (
        f"positive control: expected DescribeIdentityPool to echo {pool_id!r}, got {owner_described!r}"
    )
    owner_roles = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert owner_roles["IdentityPoolId"] == pool_id, (
        f"positive control: expected GetIdentityPoolRoles to echo {pool_id!r}, got {owner_roles!r}"
    )

    foreign_pool_id = f"{ctx.region}:{uuid.uuid4()}"

    expected_message = f"IdentityPool '{foreign_pool_id}' not found."

    code, message = _error(lambda: ev.describe_identity_pool(IdentityPoolId=foreign_pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DescribeIdentityPool on a nonexistent pool, got {code}"
    )
    assert message == expected_message, (
        f"DescribeIdentityPool: expected message {expected_message!r}, got {message!r}"
    )

    code, message = _error(lambda: ev.get_identity_pool_roles(IdentityPoolId=foreign_pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetIdentityPoolRoles on a nonexistent pool, got {code}"
    )
    assert message == expected_message, (
        f"GetIdentityPoolRoles: expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
