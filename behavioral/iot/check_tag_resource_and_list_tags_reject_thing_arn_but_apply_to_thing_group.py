"""tag-resource-and-list-tags-reject-thing-arn-but-apply-to-thing-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-reject-thing-arn-but-apply-to-thing-group"
GROUP = "thing-tagging"
SERVICES = ["iot"]

_INVALID_RESOURCE_TYPE = ("InvalidRequestException", "Invalid resource type in ARN: thing")


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises; raises if ``fn`` unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _group_tags(iot, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in iot.list_tags_for_resource(resourceArn=arn)["tags"]}


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """ListTagsForResource and TagResource both refuse a thing ARN with
    InvalidRequestException "Invalid resource type in ARN: thing", while the same two calls
    against a thing-group ARN return and then modify the group's tags.

    Reference: https://docs.aws.amazon.com/iot/latest/apireference/API_TagResource.html
    """
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-behav-thing-tagreject-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    group_name = ctx.unique_name("sim2real-behav-group-tagreject-")
    group_arn = iot.create_thing_group(
        thingGroupName=group_name,
        tags=[{"Key": "env", "Value": "dev"}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    initial = _group_tags(iot, group_arn)
    assert initial == {"env": "dev"}, (
        f"positive control: expected the create-time tag on the thing group, got {initial!r}"
    )

    list_err = _error(lambda: iot.list_tags_for_resource(resourceArn=thing_arn))
    assert list_err == _INVALID_RESOURCE_TYPE, (
        f"ListTagsForResource on a thing ARN returned {list_err!r}, expected {_INVALID_RESOURCE_TYPE!r}"
    )

    tag_err = _error(
        lambda: iot.tag_resource(resourceArn=thing_arn, tags=[{"Key": "owner", "Value": "fleet"}])
    )
    assert tag_err == _INVALID_RESOURCE_TYPE, (
        f"TagResource on a thing ARN returned {tag_err!r}, expected {_INVALID_RESOURCE_TYPE!r}"
    )

    untouched = _group_tags(iot, group_arn)
    assert untouched == initial, (
        f"the thing group's tags changed to {untouched!r} after the refused thing-ARN calls, "
        f"expected them to stay {initial!r}"
    )

    iot.tag_resource(
        resourceArn=group_arn,
        tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "fleet"}],
    )
    updated = _group_tags(iot, group_arn)
    want = {"env": "prod", "owner": "fleet"}
    assert updated == want, (
        f"after TagResource on the thing group, tags read back as {updated!r}, expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
