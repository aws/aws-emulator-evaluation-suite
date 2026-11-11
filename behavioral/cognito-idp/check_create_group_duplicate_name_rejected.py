"""create-group-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-duplicate-name-rejected"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup with an existing GroupName is refused with GroupExistsException "A group with the
    name already exists." and leaves the original Description, while a group with another name is
    created and readable."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-dupgrp-pool-"))["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-dupgrp-")
    cognito.create_group(GroupName=group_name, UserPoolId=pool_id, Description="original")

    code, message = _error(
        lambda: cognito.create_group(
            GroupName=group_name, UserPoolId=pool_id, Description="clobbered"
        )
    )
    assert code == "GroupExistsException", (
        f"expected GroupExistsException for a duplicate GroupName, got {code!r}"
    )
    assert message == "A group with the name already exists.", (
        f"expected the exact duplicate-group message, got {message!r}"
    )

    # Effect absent: the duplicate attempt did not overwrite the existing group.
    group = cognito.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]
    assert group["Description"] == "original", (
        f"expected the original Description to survive the rejected duplicate, got {group['Description']!r}"
    )

    # Positive control: a genuinely new group name still succeeds, confirmed via an
    # independent GetGroup rather than the create call's own echoed response.
    other_name = ctx.unique_name("sim2real-dupgrp-ctrl-")
    cognito.create_group(GroupName=other_name, UserPoolId=pool_id)
    control = cognito.get_group(GroupName=other_name, UserPoolId=pool_id)["Group"]
    assert control["GroupName"] == other_name, (
        f"expected control group {other_name!r} to be independently readable, got {control!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected CreateGroup to reject the duplicate GroupName, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
