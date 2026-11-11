"""tag-resource-nonexistent-resource-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-arn-rejected"
GROUP = "tagging"
SERVICES = ["mediapackagev2"]


RESOURCE_NOT_FOUND = "Resource was not found"


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected success raises, so a target that
    accepts a tag write real AWS refuses cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a well-formed ARN naming no resource both fail
    NotFoundException with the exact message and no tag reaches a real channel group, while tagging the
    real group's ARN succeeds."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control is created first so the fabricated-ARN write below can be
    # checked for bleed against it, not just reasoned about.
    group = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    real_arn = created["Arn"]

    nonexistent_name = ctx.unique_name("sim2real-mpkg-cg-ghost-")
    fake_arn = (
        f"arn:aws:mediapackagev2:{ctx.region}:{account_id}:channelGroup/{nonexistent_name}"
    )
    err = _client_error(
        lambda: mp.tag_resource(ResourceArn=fake_arn, Tags={"ghost-key": "ghost-value"})
    )
    code = err.response["Error"]["Code"]
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == RESOURCE_NOT_FOUND, (
        f"expected message {RESOURCE_NOT_FOUND!r}, got {message!r}"
    )

    # Effect absent: no tag record exists under the fabricated ARN.
    list_err = _client_error(lambda: mp.list_tags_for_resource(ResourceArn=fake_arn))
    list_code = list_err.response["Error"]["Code"]
    assert list_code == "NotFoundException", f"expected NotFoundException, got {list_code!r}"
    list_message = list_err.response["Error"]["Message"]
    assert list_message == RESOURCE_NOT_FOUND, (
        f"expected message {RESOURCE_NOT_FOUND!r}, got {list_message!r}"
    )

    # The real ChannelGroup must show no trace of the
    # fabricated-ARN write. A distinct key (never used on real_arn) means this
    # actually detects cross-ARN bleed rather than being masked by the positive
    # control below reusing the same key.
    real_tags_before = mp.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert "ghost-key" not in real_tags_before, (
        f"tag write on fabricated ARN {fake_arn} bled into real resource {real_arn}: {real_tags_before}"
    )

    # Positive control: a real ChannelGroup ARN accepts and round-trips its own tag.
    mp.tag_resource(ResourceArn=real_arn, Tags={"k": "v"})
    real_tags_after = mp.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert real_tags_after.get("k") == "v", (
        f"tag write on {real_arn} did not round-trip: {real_tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
