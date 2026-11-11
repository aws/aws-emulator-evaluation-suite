"""tag-list-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "tag-list-untag-roundtrip"
GROUP = 'tags'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource round-trip is reflected by ListTagsForResource."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    resp = ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    arn = resp["EventBusArn"]
    ev.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "test"}])
    listed = ev.list_tags_for_resource(ResourceARN=arn)
    tags = {t["Key"]: t["Value"] for t in listed.get("Tags", [])}
    assert tags.get("env") == "test", f"expected tag env=test after TagResource, got {tags}"
    ev.untag_resource(ResourceARN=arn, TagKeys=["env"])
    listed2 = ev.list_tags_for_resource(ResourceARN=arn)
    tags2 = {t["Key"]: t["Value"] for t in listed2.get("Tags", [])}
    assert "env" not in tags2, f"expected tag env removed after UntagResource, still present in {tags2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
