"""e2e-delete-user-pool-deletion-protection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-delete-user-pool-deletion-protection-rejected"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPool on a pool with DeletionProtection=ACTIVE is rejected, leaves the
    pool intact, and the identical call succeeds once protection is turned off.
    """
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        DeletionProtection="ACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_pool(cognito, pool_id))

    code, message = _error(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException while deletion protection is ACTIVE, got {code}"
    )
    expected = (
        "The user pool cannot be deleted because deletion protection is activated. "
        "Deletion protection must be inactivated first."
    )
    assert message == expected, (
        f"expected the exact InvalidParameterException message {expected!r}, got {message!r}"
    )

    # Effect absent: the pool must still exist, untouched.
    still_there = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert still_there["Id"] == pool_id, "pool disappeared despite the rejected delete"

    # Positive control: the very same delete call succeeds once protection is off.
    cognito.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    cognito.delete_user_pool(UserPoolId=pool_id)

    gone_code, gone_message = _error(lambda: cognito.describe_user_pool(UserPoolId=pool_id))
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {gone_code}"
    )
    expected_gone = f"User pool {pool_id} does not exist."
    assert gone_message == expected_gone, (
        f"expected the exact ResourceNotFoundException message {expected_gone!r}, got {gone_message!r}"
    )

    # A mutation on the now-dead id must also fail, not just a read.
    dead_code, dead_message = _error(
        lambda: cognito.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted pool, got {dead_code}"
    )
    # AWS refuses UpdateUserPool on a deleted pool with an empty message.
    assert dead_message == "", (
        f"expected the exact ResourceNotFoundException message '', got {dead_message!r}"
    )


def _safe_delete_pool(cognito, pool_id: str) -> None:
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except cognito.exceptions.ResourceNotFoundException:
        pass


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
