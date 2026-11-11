"""tag-resource-concurrent-writes-all-persist."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-writes-all-persist"
GROUP = "concurrency"
SERVICES = ["groundstation"]

_RACER_COUNT = 8


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent TagResource calls against the same Config, each adding a distinct tag key,
    all land in the tag map -- no lost update even though every racer mutates the same resource."""
    gs = ctx.client("groundstation")
    created = gs.create_config(
        name=ctx.unique_name("sim2real-gs-race-"),
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
    )
    config_id, config_type, arn = created["configId"], created["configType"], created["configArn"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=config_id, configType=config_type))

    expected = {f"racer-{i}": str(i) for i in range(_RACER_COUNT)}

    def _tag_one(key, value):
        gs.tag_resource(resourceArn=arn, tags={key: value})

    with ThreadPoolExecutor(max_workers=_RACER_COUNT) as pool:
        futures = [pool.submit(_tag_one, k, v) for k, v in expected.items()]
        for fut in as_completed(futures):
            fut.result()

    final_tags = gs.list_tags_for_resource(resourceArn=arn)["tags"]
    for key, value in expected.items():
        actual = final_tags.get(key)
        assert actual == value, (
            f"lost update for tag {key!r}: expected {value!r}, got {actual!r} (all tags: {final_tags!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
