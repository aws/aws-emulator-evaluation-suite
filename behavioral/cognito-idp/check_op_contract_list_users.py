"""op-contract-list-users."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-users"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListUsers returns every user created in the pool; an invalid filter expression is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    username_a = ctx.unique_name("sim2real-user-a-")
    username_b = ctx.unique_name("sim2real-user-b-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username_a, MessageAction="SUPPRESS")
    idp.admin_create_user(UserPoolId=pool_id, Username=username_b, MessageAction="SUPPRESS")

    users = []
    token = None
    while True:
        kwargs = {"UserPoolId": pool_id}
        if token:
            kwargs["PaginationToken"] = token
        resp = idp.list_users(**kwargs)
        users.extend(resp["Users"])
        token = resp.get("PaginationToken")
        if not token:
            break

    usernames = {u["Username"] for u in users}
    assert username_a in usernames and username_b in usernames, usernames

    err = _client_error(
        lambda: idp.list_users(UserPoolId=pool_id, Filter="this is not a valid filter expression")
    )
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err!r}"
    want = "Error while parsing filter."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
