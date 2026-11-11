"""tag-resource-invalid-tag-key-format-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-tag-key-format-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a tag key using the reserved `aws:` prefix is rejected
    rather than being silently truncated or stripped of its prefix."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-badtag-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": "aws:reserved", "value": "x"}])
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "Tag key must not start with aws:", f"unexpected error message: {message!r}"

    # Effect absent: the reserved-prefixed tag never landed on the resource.
    tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert all(t["key"] != "aws:reserved" for t in tags), f"reserved tag key leaked: {tags}"

    # Positive control: a normally-formed tag key succeeds.
    ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": "sim2real-owner", "value": "batch-03"}])
    tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert {"key": "sim2real-owner", "value": "batch-03"} in tags, f"expected owner tag present, got {tags!r}"


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
