"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named key, leaving other tags on the resource intact."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=name, tags={"keepme": "1", "dropme": "1"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    monitor_arn = created["monitorArn"]

    nm.untag_resource(resourceArn=monitor_arn, tagKeys=["dropme"])
    tags_after = nm.list_tags_for_resource(resourceArn=monitor_arn)["tags"]
    assert "dropme" not in tags_after, "untagged key must be gone"
    assert tags_after.get("keepme") == "1", "unrelated tag must survive untagging"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
