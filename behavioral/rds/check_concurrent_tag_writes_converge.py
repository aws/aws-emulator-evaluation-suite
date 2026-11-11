"""concurrent-tag-writes-converge."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-writes-converge"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AddTagsToResource calls sharing one key converge: that key holds exactly one
    of the two racing values with no duplicate entry, and each racer's unique key survives."""
    rds = ctx.client("rds")
    group_name = ctx.unique_name("sim2real-rds-tagcpg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=group_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real tag concurrency test group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=group_name))
    resource_arn = rds.describe_db_parameter_groups(DBParameterGroupName=group_name)[
        "DBParameterGroups"
    ][0]["DBParameterGroupArn"]

    def _tag_a():
        return rds.add_tags_to_resource(
            ResourceName=resource_arn,
            Tags=[{"Key": "Env", "Value": "blue"}, {"Key": "RacerA", "Value": "a-value"}],
        )

    def _tag_b():
        return rds.add_tags_to_resource(
            ResourceName=resource_arn,
            Tags=[{"Key": "Env", "Value": "green"}, {"Key": "RacerB", "Value": "b-value"}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_tag_a)
        fut_b = pool.submit(_tag_b)
        fut_a.result()
        fut_b.result()

    raw_tags = rds.list_tags_for_resource(ResourceName=resource_arn)["TagList"]
    env_entries = [t for t in raw_tags if t["Key"] == "Env"]
    assert len(env_entries) == 1, f"expected exactly one Env tag entry, got {env_entries}"
    assert env_entries[0]["Value"] in ("blue", "green"), (
        f"Env tag value {env_entries[0]['Value']!r} matches neither racer -- corrupted write"
    )

    tags_by_key = {t["Key"]: t["Value"] for t in raw_tags}
    assert tags_by_key.get("RacerA") == "a-value", "racer A's unique tag was lost"
    assert tags_by_key.get("RacerB") == "b-value", "racer B's unique tag was lost"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
