"""tag-resource-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "data-plane"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource (and on the resource's own
    describe/list); UntagResource removes exactly the requested key."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"))["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    arn = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["arn"]

    amp.tag_resource(resourceArn=arn, tags={"sim2real-owner": "behavioral", "sim2real-keep": "yes"})
    tags = amp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-owner") == "behavioral", f"expected sim2real-owner=='behavioral', got {tags.get('sim2real-owner')!r}"
    assert tags.get("sim2real-keep") == "yes", f"expected sim2real-keep=='yes', got {tags.get('sim2real-keep')!r}"
    described_tags = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["tags"]
    assert described_tags == tags, f"describe_workspace tags {described_tags!r} diverge from list_tags_for_resource tags {tags!r}"

    amp.untag_resource(resourceArn=arn, tagKeys=["sim2real-owner"])
    remaining = amp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-owner" not in remaining, f"expected sim2real-owner removed after untag_resource, still present in {remaining!r}"
    assert remaining.get("sim2real-keep") == "yes", f"expected sim2real-keep to survive untag_resource, got {remaining.get('sim2real-keep')!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
