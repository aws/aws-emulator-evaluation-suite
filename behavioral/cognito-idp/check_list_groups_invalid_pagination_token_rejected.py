"""list-groups-invalid-pagination-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-groups-invalid-pagination-token-rejected"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListGroups fails with InvalidParameterException and its exact message for a well-formed but
    unissued NextToken, while tokenless listings before and after return the group."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-lgtok-pool-"))["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-lgtok-grp-")
    cognito.create_group(GroupName=group_name, UserPoolId=pool_id)

    # Positive control: an ordinary listing succeeds and finds the group.
    control = cognito.list_groups(UserPoolId=pool_id)
    assert any(g["GroupName"] == group_name for g in control["Groups"]), (
        f"positive control did not see {group_name!r} in {control['Groups']!r}"
    )

    code, message = _error(
        lambda: cognito.list_groups(UserPoolId=pool_id, NextToken="not-a-real-continuation-token")
    )
    assert code == "InvalidParameterException", (
        f"a nonsensical NextToken was rejected with {code!r}, expected 'InvalidParameterException'"
    )
    expected = "Provided pagination token is invalid. Check the token and try your request again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call did not disturb the pool's group set.
    after = {g["GroupName"] for g in cognito.list_groups(UserPoolId=pool_id)["Groups"]}
    assert after == {group_name}, (
        f"the rejected call left the pool's group set as {after!r}, expected {{{group_name!r}}}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
