"""list-groups-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-groups-invalid-next-token-rejected"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups returns the pool's one group, fails with InvalidParameterException and its exact
    message for a NextToken the service never issued, and returns the group again afterwards."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    name = ctx.unique_name("sim2real-behav-group-")
    cognito.create_group(GroupName=name, UserPoolId=pool_id)

    good = cognito.list_groups(UserPoolId=pool_id)
    assert {g["GroupName"] for g in good.get("Groups", [])} == {name}, (
        f"positive control did not see exactly the created group: {good.get('Groups')!r}"
    )

    code, message = _error(
        lambda: cognito.list_groups(UserPoolId=pool_id, NextToken="not-a-real-pagination-token")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = "Provided pagination token is invalid. Check the token and try your request again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control still works after the rejected call
    good2 = cognito.list_groups(UserPoolId=pool_id)
    assert {g["GroupName"] for g in good2.get("Groups", [])} == {name}, (
        f"pool state corrupted by the rejected call: {good2.get('Groups')!r}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {"PoolName": ctx.unique_name("sim2real-behav-pool-")}
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
