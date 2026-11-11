"""concurrent-tag-resource-no-lost-writes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-no-lost-writes"
GROUP = "concurrency"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls against the same connection, each adding a distinct
    tag key, must all be preserved: TagResource is an additive merge, so no concurrent
    writer's tag should be lost even though every call targets the same resource."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    keys = [f"tag-{i}" for i in range(10)]

    def _tag(key: str) -> None:
        cc.tag_resource(ResourceArn=arn, Tags=[{"Key": key, "Value": key}])

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(_tag, keys))

    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    for key in keys:
        assert tags.get(key) == key, f"lost concurrent write for tag key {key!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
