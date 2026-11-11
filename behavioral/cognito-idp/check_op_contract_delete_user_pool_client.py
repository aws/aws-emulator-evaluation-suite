"""op-contract-delete-user-pool-client."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-user-pool-client"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClient removes the client (confirmed via a post-delete 404) and
    rejects a second delete of that same, now-gone ClientId with the right code."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    # positive control: the client is genuinely describable before we touch it, so the
    # post-delete not-found below is attributable to the delete and not to a describe
    # endpoint that always reports not-found
    described = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert described["ClientId"] == client_id, f"expected freshly created client to be describable, got {described!r}"

    # success path: delete succeeds and the client is truly gone afterwards
    idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    code, message = _error(lambda: idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    assert code == "ResourceNotFoundException", f"expected client gone after delete, got {code!r}"
    assert message == "User pool client does not exist.", f"DescribeUserPoolClient: message {message!r}"

    # distinct error boundary: deleting the already-deleted client a second time is
    # still rejected as ResourceNotFoundException, not silently accepted (not idempotent)
    second_code, second_message = _error(
        lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    assert second_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {second_code!r}"
    assert second_message == f"User pool client {client_id} does not exist.", (
        f"second DeleteUserPoolClient: message {second_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
