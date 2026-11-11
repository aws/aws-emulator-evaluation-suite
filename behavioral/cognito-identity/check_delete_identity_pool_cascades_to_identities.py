"""delete-identity-pool-cascades-to-identities."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-pool-cascades-to-identities"
GROUP = "state"
SERVICES = ["cognito-identity"]


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an identity pool makes the pool and its identities irrecoverably not-found."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ci, pool_id))
    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]

    pool_before = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert pool_before["IdentityPoolId"] == pool_id, (
        f"positive control: pool must exist before deletion, got {pool_before}"
    )
    identity_before = ci.describe_identity(IdentityId=identity_id)
    assert identity_before["IdentityId"] == identity_id, (
        f"positive control: identity must resolve before pool deletion, got {identity_before}"
    )

    ci.delete_identity_pool(IdentityPoolId=pool_id)

    expected = f"IdentityPool '{pool_id}' not found."
    code, message = _error(lambda: ci.describe_identity_pool(IdentityPoolId=pool_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code_get_id, message = _error(lambda: ci.get_id(IdentityPoolId=pool_id))
    assert code_get_id == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_get_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The orphaned identity is refused by naming its deleted pool, not the identity itself.
    code_describe_identity, message = _error(lambda: ci.describe_identity(IdentityId=identity_id))
    assert code_describe_identity == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for orphaned identity, got {code_describe_identity}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
