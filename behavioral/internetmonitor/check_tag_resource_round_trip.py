"""tag-resource-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-round-trip"
GROUP = "tags"
SERVICES = ["internetmonitor"]


def _safe_delete_monitor(im, name, timeout_s=60.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete."""
    try:
        im.update_monitor(MonitorName=name, Status="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = im.get_monitor(MonitorName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    im.delete_monitor(MonitorName=name)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes exactly the requested keys."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-tag-")
    created = im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    im.tag_resource(ResourceArn=arn, Tags={"env": "sim2real", "keep": "yes"})

    deadline = time.monotonic() + 30.0
    tags = {}
    while time.monotonic() < deadline:
        tags = im.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
        if tags.get("env") == "sim2real" and tags.get("keep") == "yes":
            break
        time.sleep(1.0)
    assert tags.get("env") == "sim2real", f"expected tag env=sim2real, got {tags!r}"
    assert tags.get("keep") == "yes", f"expected tag keep=yes, got {tags!r}"

    im.untag_resource(ResourceArn=arn, TagKeys=["env"])

    deadline = time.monotonic() + 30.0
    tags = {}
    while time.monotonic() < deadline:
        tags = im.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
        if "env" not in tags:
            break
        time.sleep(1.0)
    assert "env" not in tags, f"expected env tag removed by UntagResource, still present in {tags!r}"
    assert tags.get("keep") == "yes", f"expected untouched tag keep=yes to survive UntagResource, got {tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
