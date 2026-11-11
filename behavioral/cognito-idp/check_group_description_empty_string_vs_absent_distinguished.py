"""group-description-empty-string-vs-absent-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-description-empty-string-vs-absent-distinguished"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup omits Description both for a group created with an empty Description and for one created
    without it, and returns a non-empty Description verbatim."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-grppool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    group_with_empty = ctx.unique_name("sim2real-grp-empty-")
    group_without = ctx.unique_name("sim2real-grp-absent-")
    group_with_text = ctx.unique_name("sim2real-grp-text-")

    idp.create_group(UserPoolId=pool_id, GroupName=group_with_empty, Description="")
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_with_empty))

    idp.create_group(UserPoolId=pool_id, GroupName=group_without)
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_without))

    idp.create_group(UserPoolId=pool_id, GroupName=group_with_text, Description="a real description")
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_with_text))

    got_with_empty = idp.get_group(UserPoolId=pool_id, GroupName=group_with_empty)["Group"]
    got_without = idp.get_group(UserPoolId=pool_id, GroupName=group_without)["Group"]
    got_with_text = idp.get_group(UserPoolId=pool_id, GroupName=group_with_text)["Group"]

    # empty-string and omitted collapse to the identical (absent) representation
    assert "Description" not in got_with_empty, f"expected Description omitted, got {got_with_empty!r}"
    assert "Description" not in got_without, f"expected Description omitted, got {got_without!r}"

    # but a real, non-empty description is preserved byte-identical
    assert got_with_text.get("Description") == "a real description", (
        f"expected Description='a real description', got {got_with_text.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
