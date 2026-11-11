"""untag-resource-arn-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-arn-removes-tag"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource on a generic resource ARN drives tag state through
    tagged -> partially-untagged -> fully-untagged, and ListTagsForResource
    reflects each transition."""
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert len(described) == 1, f"expected exactly 1 log group named {log_group}, got {described}"
    arn = described[0]["arn"]
    # describe_log_groups returns the ARN with a trailing ":*" wildcard
    # suffix; the tagging APIs (ListTagsForResource/TagResource/
    # UntagResource) reject that suffix with ValidationException, so it
    # must be stripped before use.
    if arn.endswith(":*"):
        arn = arn[: -len(":*")]

    # starting state: no tags
    initial_tags = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert initial_tags == {}, f"expected a freshly-created log group to have no tags, got {initial_tags}"

    logs.tag_resource(
        resourceArn=arn, tags={"Environment": "sim2real-test", "Owner": "behavioral"}
    )
    tagged = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tagged.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test after TagResource, got {tagged.get('Environment')!r}"
    )
    assert tagged.get("Owner") == "behavioral", (
        f"expected Owner=behavioral after TagResource, got {tagged.get('Owner')!r}"
    )

    # remove one of the two tags
    logs.untag_resource(resourceArn=arn, tagKeys=["Environment"])
    partially_untagged = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "Environment" not in partially_untagged, (
        f"Environment tag still present after UntagResource: {partially_untagged}"
    )
    assert partially_untagged.get("Owner") == "behavioral", "unrelated tag must survive"

    # remove the remaining tag
    logs.untag_resource(resourceArn=arn, tagKeys=["Owner"])
    fully_untagged = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert fully_untagged == {}, f"expected no tags left, got {fully_untagged}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
