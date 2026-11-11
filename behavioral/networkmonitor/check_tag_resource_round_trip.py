"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at CreateMonitor time and tags added later via TagResource are both visible
    through ListTagsForResource on the monitor's ARN.
    """
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=name, tags={"env": "sim2real-created"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    monitor_arn = created["monitorArn"]

    tags_after_create = nm.list_tags_for_resource(resourceArn=monitor_arn)["tags"]
    assert tags_after_create.get("env") == "sim2real-created", (
        f"expected env=sim2real-created from CreateMonitor tags, got {tags_after_create!r}"
    )

    nm.tag_resource(resourceArn=monitor_arn, tags={"owner": "sim2real-added"})
    tags_after_tag = nm.list_tags_for_resource(resourceArn=monitor_arn)["tags"]
    assert tags_after_tag.get("env") == "sim2real-created", (
        f"expected env=sim2real-created to survive TagResource, got {tags_after_tag!r}"
    )
    assert tags_after_tag.get("owner") == "sim2real-added", (
        f"expected owner=sim2real-added from TagResource, got {tags_after_tag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
