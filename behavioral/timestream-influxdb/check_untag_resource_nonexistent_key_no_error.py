"""untag-resource-nonexistent-key-no-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-no-error"
GROUP = "tagging"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tag key that was never set on the resource is a no-op: it
    does not raise and leaves the resource's existing tags untouched."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-untagnoop-")
    pg = influx.create_db_parameter_group(name=name)
    arn = pg["arn"]

    influx.tag_resource(resourceArn=arn, tags={"env": "sim2real"})
    # Timestream for InfluxDB has no DeleteDbParameterGroup API, so this lightweight
    # metadata object is intentionally left in the account (no cleanup call is
    # possible); ctx.unique_name keeps it from colliding with other runs.

    # This key was never attached; removing it must succeed without error.
    influx.untag_resource(resourceArn=arn, tagKeys=["never-set-key"])

    tags = influx.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("env") == "sim2real", f"expected env=sim2real to survive untag of an unrelated key, got {tags}"
    assert "never-set-key" not in tags, f"never-set-key was never attached but appears in tags: {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
