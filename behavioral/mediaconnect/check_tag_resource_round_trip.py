"""tag-resource-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags that are visible via ListTagsForResource; UntagResource
    removes a specific key while leaving the others in place; DeleteFlow then removes the
    tagged resource entirely, proven by an independent DescribeFlow NotFoundException."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_flow(FlowArn=flow_arn), mc.exceptions.NotFoundException))

    mc.tag_resource(ResourceArn=flow_arn, Tags={"env": "sim2real-test", "team": "media"})
    result = mc.list_tags_for_resource(ResourceArn=flow_arn)["Tags"]
    assert result["env"] == "sim2real-test", (
        f"expected tag env=sim2real-test after TagResource, got {result.get('env')!r}"
    )
    assert result["team"] == "media", (
        f"expected tag team=media after TagResource, got {result.get('team')!r}"
    )

    mc.untag_resource(ResourceArn=flow_arn, TagKeys=["team"])
    result = mc.list_tags_for_resource(ResourceArn=flow_arn)["Tags"]
    assert "team" not in result, f"expected team tag removed after UntagResource, still present in {result!r}"
    assert result["env"] == "sim2real-test", (
        f"expected env tag to survive UntagResource(TagKeys=[team]), got {result.get('env')!r}"
    )

    mc.delete_flow(FlowArn=flow_arn)
    code, message = _poll_for_not_found(mc, flow_arn, timeout_s=120)
    assert code == "NotFoundException", (
        f"expected NotFoundException from DescribeFlow after DeleteFlow, got {code!r}"
    )
    expected = f"Not found: {flow_arn}"
    assert message == expected, (
        f"expected message {expected!r} from DescribeFlow after DeleteFlow, got {message!r}"
    )


def _poll_for_not_found(mc, flow_arn: str, timeout_s: float):
    """Poll DescribeFlow until it raises; return that error's (code, message), or the
    last (code, message) seen when the budget runs out (None, None while still describable)."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            mc.describe_flow(FlowArn=flow_arn)
            last = (None, None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == "NotFoundException":
                return last
        time.sleep(3)
    return last


def _safe(fn, not_found) -> None:
    try:
        fn()
    except not_found:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
