"""op-contract-delete-user-pool."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-delete-user-pool"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserPool actually removes the pool (confirmed via a post-delete 404, and a
    repeat delete on the now-dead pool also fails rather than silently no-op'ing) and
    rejects a structurally invalid UserPoolId before ever looking the pool up."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_pool(idp, pool_id))

    # success path: delete succeeds and the effect is real - the pool is truly gone
    idp.delete_user_pool(UserPoolId=pool_id)
    code, message = _error(lambda: idp.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", f"expected pool gone after delete, got {code!r}"
    assert message == f"User pool {pool_id} does not exist.", f"DescribeUserPool: message {message!r}"

    # a mutation on the dead id is rejected too, not treated as a no-op
    redelete_code, redelete_message = _error(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second delete on the dead pool to fail with ResourceNotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == f"User pool {pool_id} does not exist.", (
        f"second DeleteUserPool: message {redelete_message!r}"
    )

    # distinct error boundary: a structurally malformed UserPoolId is rejected as
    # InvalidParameterException, not conflated with ResourceNotFoundException
    bad_id = "not a valid pool id!!"
    bad_code, bad_message = _error(lambda: idp.delete_user_pool(UserPoolId=bad_id))
    assert bad_code == "InvalidParameterException", f"expected InvalidParameterException, got {bad_code!r}"
    assert bad_message == (
        f"1 validation error detected: Value '{bad_id}' at 'userPoolId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-zA-Z]+"
    ), f"malformed UserPoolId: message {bad_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_pool(idp, pool_id: str) -> None:
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
