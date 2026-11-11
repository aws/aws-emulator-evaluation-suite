"""op-contract-update-group-bogus-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-group-bogus-name-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup actually mutates the group's stored Description/Precedence (verified via
    GetGroup); updating a GroupName that doesn't exist is rejected with ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-behav-group-")
    idp.create_group(GroupName=group_name, UserPoolId=pool_id, Description="initial", Precedence=10)
    before = idp.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]

    idp.update_group(GroupName=group_name, UserPoolId=pool_id, Description="updated", Precedence=20)

    after = idp.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]
    assert after["Description"] == "updated", after
    assert after["Precedence"] == 20, after
    assert after["LastModifiedDate"] >= before["LastModifiedDate"]

    missing_name = group_name + "-missing"
    code, message = _error(
        lambda: idp.update_group(GroupName=missing_name, UserPoolId=pool_id, Description="x")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Group not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected UpdateGroup must not have silently
    # materialized a group under the name it was rejected for.
    lookup_code, lookup_message = _error(lambda: idp.get_group(GroupName=missing_name, UserPoolId=pool_id))
    assert lookup_code == "ResourceNotFoundException", (
        f"expected GetGroup on the rejected name to also raise ResourceNotFoundException, got {lookup_code}"
    )
    assert lookup_message == expected, f"expected message {expected!r}, got {lookup_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
