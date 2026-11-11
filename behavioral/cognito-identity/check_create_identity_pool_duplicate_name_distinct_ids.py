"""create-identity-pool-duplicate-name-distinct-ids."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-pool-duplicate-name-distinct-ids"
GROUP = 'lifecycle'
SERVICES = ['cognito-identity']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool is not name-idempotent: same name yields two distinct, independent
    pools -- deleting one must not disturb its same-named sibling."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-pool-dup-").replace("-", "_")

    resp1 = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool1_id = resp1["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ci, pool1_id))
    resp2 = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool2_id = resp2["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool2_id))

    assert pool1_id != pool2_id, (
        f"two CreateIdentityPool calls with the same name {name!r} must yield distinct "
        f"pool ids, got {pool1_id!r} for both"
    )

    desc1 = ci.describe_identity_pool(IdentityPoolId=pool1_id)
    desc2 = ci.describe_identity_pool(IdentityPoolId=pool2_id)
    assert desc1["IdentityPoolName"] == name, (
        f"expected pool {pool1_id} to keep name {name!r}, got {desc1['IdentityPoolName']!r}"
    )
    assert desc2["IdentityPoolName"] == name, (
        f"expected pool {pool2_id} to keep name {name!r}, got {desc2['IdentityPoolName']!r}"
    )

    # The two pools are genuinely independent, not just distinct id strings: deleting one
    # must leave the other -- same name, same account -- fully intact.
    ci.delete_identity_pool(IdentityPoolId=pool1_id)
    err, message = _error(lambda: ci.describe_identity_pool(IdentityPoolId=pool1_id))
    assert err == "ResourceNotFoundException", (
        f"expected DescribeIdentityPool on the deleted pool {pool1_id} to fail with "
        f"ResourceNotFoundException, got {err!r}"
    )
    expected = f"IdentityPool '{pool1_id}' not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    desc2_after = ci.describe_identity_pool(IdentityPoolId=pool2_id)
    assert desc2_after["IdentityPoolName"] == name, (
        f"deleting pool {pool1_id} must not affect its same-named sibling {pool2_id}, "
        f"got {desc2_after['IdentityPoolName']!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
