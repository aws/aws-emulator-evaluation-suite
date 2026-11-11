"""thing-group-tags-at-create-round-trip-and-missing-group-arn."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-group-tags-at-create-round-trip-and-missing-group-arn"
GROUP = "tagging"
SERVICES = ["iot"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Thing-group tags from CreateThingGroup, TagResource and UntagResource read back exactly via
    ListTagsForResource. On the ARN of a never-created group ListTagsForResource reads back empty
    and TagResource is refused with ResourceNotFoundException; the real group is untouched.

    Reference: https://docs.aws.amazon.com/iot/latest/apireference/API_ListTagsForResource.html
    """
    iot = ctx.client("iot")

    name = ctx.unique_name("sim2real-behav-tgtags-")
    arn = iot.create_thing_group(
        thingGroupName=name,
        tags=[{"Key": "team", "Value": "fleet"}, {"Key": "env", "Value": "dev"}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=name))

    got = _tags(iot, arn)
    assert got == {"team": "fleet", "env": "dev"}, f"create-time tags read back as {got!r}"

    iot.tag_resource(
        resourceArn=arn, tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "ops"}]
    )
    got = _tags(iot, arn)
    want = {"team": "fleet", "env": "prod", "owner": "ops"}
    assert got == want, f"after TagResource the tags read back as {got!r}, expected {want!r}"

    iot.untag_resource(resourceArn=arn, tagKeys=["team"])
    got = _tags(iot, arn)
    want = {"env": "prod", "owner": "ops"}
    assert got == want, f"after UntagResource the tags read back as {got!r}, expected {want!r}"

    # The same ARN form naming a group that was never created.
    missing = ctx.unique_name("sim2real-behav-tgtags-missing-")
    missing_arn = arn[: -len(name)] + missing

    missing_read = iot.list_tags_for_resource(resourceArn=missing_arn)["tags"]
    assert missing_read == [], (
        f"ListTagsForResource on a never-created group must read back empty, got {missing_read!r}"
    )

    err = _error(
        lambda: iot.tag_resource(resourceArn=missing_arn, tags=[{"Key": "k", "Value": "v"}])
    )
    want_err = ("ResourceNotFoundException", f"Thing Group {missing} does not exist.")
    assert err == want_err, (
        f"TagResource on a missing group returned {err!r}, expected {want_err!r}"
    )

    got = _tags(iot, arn)
    assert got == want, f"the real group's tags changed to {got!r} after the refused calls"


# ===== helpers =====


def _tags(iot, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in iot.list_tags_for_resource(resourceArn=arn)["tags"]}


def _error(fn) -> tuple:
    """(code, message) of the AWS error ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"call unexpectedly succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
