"""op-contract-list-user-pools."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-user-pools"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUserPools paginates to find a created pool; a malformed pagination token is rejected."""
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool_id = _create_user_pool(ctx, PoolName=pool_name)

    found = None
    token = None
    for _ in range(200):  # bounded pagination walk across the account's pools
        kwargs = {"MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        resp = idp.list_user_pools(**kwargs)
        for pool in resp["UserPools"]:
            if pool["Id"] == pool_id:
                found = pool
                break
        if found:
            break
        token = resp.get("NextToken")
        if not token:
            break

    assert found is not None, f"pool {pool_id} not found via ListUserPools"
    assert found["Name"] == pool_name, found["Name"]

    err = _client_error(
        lambda: idp.list_user_pools(MaxResults=60, NextToken="not-a-real-pagination-token")
    )
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err!r}"
    want = "Invalid pagination token given."
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
        "UserPoolTags": {"sim2real": "behavioral"},
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
