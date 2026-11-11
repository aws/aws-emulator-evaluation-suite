"""create-duplicate-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: creating a group with a name that already exists MUST fail,
    the original group's attributes must be left untouched by the rejected attempt, and creating
    a genuinely new group name must still succeed."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=name, Description="original")
    ctx.on_cleanup(lambda _p=pool_id, _g=name: c.delete_group(UserPoolId=_p, GroupName=_g))

    try:
        c.create_group(UserPoolId=pool_id, GroupName=name, Description="clobbered")
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "GroupExistsException", (
        f"expected GroupExistsException for duplicate group, got {code}"
    )
    assert message == "A group with the name already exists.", (
        f"expected the exact duplicate-group message, got {message!r}"
    )

    # Effect absent: the rejected duplicate attempt did not overwrite the original group.
    group = c.get_group(UserPoolId=pool_id, GroupName=name)["Group"]
    assert group["Description"] == "original", (
        f"expected original group description untouched, got {group['Description']!r}"
    )

    # Positive control: a genuinely new group name still succeeds after the rejection.
    other_name = ctx.unique_name("sim2real-behav-cip-group-ctrl-")
    ctx.on_cleanup(lambda _p=pool_id, _g=other_name: c.delete_group(UserPoolId=_p, GroupName=_g))
    control = c.create_group(UserPoolId=pool_id, GroupName=other_name)["Group"]
    assert control["GroupName"] == other_name, (
        f"expected control group creation to succeed with name {other_name!r}, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
