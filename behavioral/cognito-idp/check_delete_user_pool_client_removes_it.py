"""delete-user-pool-client-removes-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-pool-client-removes-it"
GROUP = 'user-pool-client-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClient makes the client disappear from DescribeUserPoolClient, and the
    dead client id also rejects a subsequent mutation rather than silently accepting it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _ignore_not_found(lambda: c.delete_user_pool(UserPoolId=_id)))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"))["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: _ignore_not_found(
            lambda: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
    )

    c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)

    code, message = _error(
        lambda: c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code}"
    )
    assert message == "User pool client does not exist.", f"DescribeUserPoolClient: message {message!r}"

    update_code, update_message = _error(
        lambda: c.update_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id, ClientName="sim2real-behav-cip-should-not-apply"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted client id to also be rejected as "
        f"ResourceNotFoundException, got {update_code}"
    )
    assert update_message == "User pool client does not exist.", (
        f"UpdateUserPoolClient on the deleted client: message {update_message!r}"
    )


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
