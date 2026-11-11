"""deletion-protection-inactive-allows-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-inactive-allows-delete"
GROUP = 'user-pool-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Flipping DeletionProtection to INACTIVE unblocks DeleteUserPool."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}, DeletionProtection="ACTIVE")["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _safe_delete_pool(c, _id))

    c.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc.get("DeletionProtection") == "INACTIVE", (
        f"expected DeletionProtection INACTIVE, got {desc.get('DeletionProtection')}"
    )

    c.delete_user_pool(UserPoolId=pool_id)

    code, message = _error(lambda: c.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code}"
    )
    assert message == f"User pool {pool_id} does not exist.", f"DescribeUserPool: message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _safe_delete_pool(client, pool_id: str) -> None:
    try:
        client.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
