"""group-description-exceeds-max-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-description-exceeds-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects a Description longer than its documented 2048-character maximum
    with InvalidParameterException, the group is never created, and a normal-length
    Description in the same pool still succeeds (positive control)."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-grplenpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:check": "group-description-exceeds-max-length-rejected"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    bad_group = ctx.unique_name("sim2real-grp-toolong-")
    too_long_description = "x" * 2049

    code, message = _rejected_error(
        lambda: idp.create_group(UserPoolId=pool_id, GroupName=bad_group, Description=too_long_description)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{too_long_description}' at 'description' "
        "failed to satisfy constraint: Member must have length less than or equal to 2048"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the over-length group was never persisted.
    not_found_code, not_found_message = _rejected_error(lambda: idp.get_group(UserPoolId=pool_id, GroupName=bad_group))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created group, got {not_found_code!r}"
    )
    expected_nf = "Group not found."
    assert not_found_message == expected_nf, f"expected message {expected_nf!r}, got {not_found_message!r}"

    # Positive control: a normal-length description in the same pool succeeds.
    good_group = ctx.unique_name("sim2real-grp-ok-")
    idp.create_group(UserPoolId=pool_id, GroupName=good_group, Description="a perfectly normal description")
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=good_group))
    got = idp.get_group(UserPoolId=pool_id, GroupName=good_group)["Group"]
    assert got["Description"] == "a perfectly normal description", (
        f"expected the positive control's description to persist unchanged, got {got['Description']!r}"
    )


def _rejected_error(fn) -> tuple:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
