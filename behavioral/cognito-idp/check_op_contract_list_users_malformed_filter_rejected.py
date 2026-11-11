"""op-contract-list-users-malformed-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-users-malformed-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers enumerates created users; a Filter referencing an unsupported attribute
    is rejected with InvalidParameterException (not silently ignored / not-found)."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPassw0rd!",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    users = idp.list_users(UserPoolId=pool_id)["Users"]
    assert any(u["Username"] == username for u in users), users

    err = _client_error(
        lambda: idp.list_users(UserPoolId=pool_id, Filter='not_a_real_attribute = "x"')
    )
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err!r}"
    want = "Input fails to satisfy the constraints."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn() and return its error dict; raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
