"""concurrent-tag-resource-no-lost-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls that each add a distinct key all land: the resource's tag set holds every
    racer's key afterwards, so no update is lost.
    """
    csc = ctx.client("codestar-connections")
    arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn))

    n = 10
    keys = [f"sim2real-race-{i}" for i in range(n)]

    def _tag(key: str) -> None:
        csc.tag_resource(ResourceArn=arn, Tags=[{"Key": key, "Value": "raced"}])

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_tag, key) for key in keys]
        for f in as_completed(futures):
            f.result()

    tags = {t["Key"]: t["Value"] for t in csc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    missing = [key for key in keys if tags.get(key) != "raced"]
    assert not missing, f"lost concurrent tag updates: {missing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
