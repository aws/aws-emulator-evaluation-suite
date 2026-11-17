"""deleted-thing-group-blocks-reads-writes-sibling-unaffected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-thing-group-blocks-reads-writes-sibling-unaffected"
GROUP = "thing-group"
SERVICES = ["iot"]


def expect_error(call, code: str, message: str) -> None:
    """Assert ``call()`` raises exactly (code, message); a success raises too, naming the result."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected error {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted thing group refuses DescribeThingGroup and UpdateThingGroup with ResourceNotFoundException,
    and ListTagsForResource on its ARN reads back no tags; a sibling group still describes untouched.
    """
    iot = ctx.client("iot")

    retired = ctx.unique_name("sim2real-behav-retired-")
    retired_arn = iot.create_thing_group(
        thingGroupName=retired,
        tags=[{"Key": "fleet", "Value": "retiring"}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: _delete_if_present(iot, retired))

    sibling = ctx.unique_name("sim2real-behav-sibling-")
    sibling_arn = iot.create_thing_group(thingGroupName=sibling)["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=sibling))

    before_delete = iot.list_tags_for_resource(resourceArn=retired_arn)["tags"]
    assert before_delete == [{"Key": "fleet", "Value": "retiring"}], (
        f"expected the create-time tag before delete, got {before_delete!r}"
    )

    iot.delete_thing_group(thingGroupName=retired)

    _describe_refusal = ("ResourceNotFoundException", f"ThingGroup {ctx.account}:{retired} not found.")
    expect_error(lambda: iot.describe_thing_group(thingGroupName=retired), *_describe_refusal)

    _update_refusal = ("ResourceNotFoundException", f"Group {retired} does not exist")
    expect_error(
        lambda: iot.update_thing_group(
            thingGroupName=retired,
            thingGroupProperties={"thingGroupDescription": "post-delete update"},
        ),
        *_update_refusal,
    )

    after_delete = iot.list_tags_for_resource(resourceArn=retired_arn)["tags"]
    assert after_delete == [], (
        f"expected no tags for the deleted group's ARN, got {after_delete!r}"
    )

    sibling_desc = iot.describe_thing_group(thingGroupName=sibling)
    assert sibling_desc["thingGroupName"] == sibling, (
        f"expected the sibling group {sibling!r} to still describe, got {sibling_desc.get('thingGroupName')!r}"
    )
    assert sibling_desc["thingGroupArn"] == sibling_arn, (
        f"expected the sibling group's ARN to be unchanged, got {sibling_desc.get('thingGroupArn')!r}"
    )


def _delete_if_present(iot, name: str) -> None:
    try:
        iot.delete_thing_group(thingGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
