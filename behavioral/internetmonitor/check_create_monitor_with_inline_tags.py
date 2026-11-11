"""create-monitor-with-inline-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-with-inline-tags"
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
    """Tags supplied on CreateMonitor are retrievable via ListTagsForResource without a separate TagResource call."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-ctag-")
    created = im.create_monitor(
        MonitorName=name, TrafficPercentageToMonitor=100, Tags={"team": "network-health"}
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    deadline = time.monotonic() + 30.0
    tags = {}
    while time.monotonic() < deadline:
        tags = im.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
        if tags:
            break
        time.sleep(1.0)

    assert tags.get("team") == "network-health", (
        f"expected tag team=network-health from inline CreateMonitor Tags, got {tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
