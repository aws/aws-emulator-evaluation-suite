"""delete-user-pool-twice-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-pool-twice-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: deleting an already-deleted user pool MUST fail."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _ignore_not_found(lambda: c.delete_user_pool(UserPoolId=_id)))
    c.delete_user_pool(UserPoolId=pool_id)

    code, message = _error(lambda: c.delete_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected second delete_user_pool to fail with ResourceNotFoundException, got {code}"
    )
    assert message == f"User pool {pool_id} does not exist.", f"second DeleteUserPool: message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    """Run a teardown call; a resource the check already deleted is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
