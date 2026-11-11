"""tag-and-untag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-lifecycle"
GROUP = "tagging"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource
    removes only the specified key while leaving the others intact."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-tags-")
    pg = influx.create_db_parameter_group(name=name)
    arn = pg["arn"]
    # Note: Timestream for InfluxDB has no DeleteDbParameterGroup API, so this
    # lightweight metadata object is intentionally left in the account (no cleanup
    # call is possible); ctx.unique_name keeps it from colliding with other runs.

    influx.tag_resource(resourceArn=arn, tags={"env": "sim2real", "team": "qa"})
    tags_after_tag = influx.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_tag.get("env") == "sim2real", f"expected env=sim2real, got {tags_after_tag!r}"
    assert tags_after_tag.get("team") == "qa", f"expected team=qa, got {tags_after_tag!r}"

    influx.untag_resource(resourceArn=arn, tagKeys=["team"])
    tags_after_untag = influx.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_untag.get("env") == "sim2real", f"expected env to survive untag, got {tags_after_untag!r}"
    assert "team" not in tags_after_untag, f"expected team removed, got {tags_after_untag!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
