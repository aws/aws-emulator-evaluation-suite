"""op-contract-describe-user-pool-client."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-user-pool-client"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeUserPoolClient returns the client's config; a bogus ClientId 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    pool_deleted = []
    ctx.on_cleanup(
        lambda: None if pool_deleted else _retry_throttled(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    )

    client_name = ctx.unique_name("sim2real-behav-client-")
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    desc = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc["ClientId"] == client_id, desc
    assert desc["ClientName"] == client_name, desc
    # Exact set, not membership: a target that silently ADDS auth flows it was not asked for
    # is an over-permissive divergence that a substring/membership assertion would miss.
    assert set(desc["ExplicitAuthFlows"]) == {
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
    }, desc["ExplicitAuthFlows"]

    err = _client_error(
        lambda: idp.describe_user_pool_client(UserPoolId=pool_id, ClientId="0" * 26)
    )
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = "User pool client does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"

    # The pool this check created is torn down again in on_cleanup, but that delete is otherwise
    # never proven: assert the independent read now 404s too, so the delete is shown to take effect.
    _retry_throttled(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    pool_deleted.append(pool_id)
    post_delete = _client_error(
        lambda: idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    assert post_delete.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {post_delete!r}"
    want = f"User pool {pool_id} does not exist."
    assert post_delete.get("Message") == want, f"expected message {want!r}, got {post_delete.get('Message')!r}"


def _retry_throttled(fn, *, max_attempts=8, base_delay=1.0):
    """DeleteUserPool cleanup must not leak the pool just because Cognito throttled it under
    concurrent load; retry TooManyRequestsException with backoff before giving up."""
    import time

    from botocore.exceptions import ClientError

    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
