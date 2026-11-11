"""concurrent-tag-merge-all-keys-persist."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-tag-merge-all-keys-persist"
GROUP = "concurrency"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent Tag() calls on distinct keys all persist -- the map merge must not drop racers."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-conctag-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-conctag-nomatch","Values":["' + name + '"]}]}',
    }
    created = rg.create_group(Name=name, ResourceQuery=query)
    arn = created["Group"]["GroupArn"]
    ctx.on_cleanup(lambda: rg.delete_group(Group=name))

    n = 10
    expected = {f"ConcKey{i}": f"v{i}" for i in range(n)}

    def _apply(i):
        rg.tag(Arn=arn, Tags={f"ConcKey{i}": f"v{i}"})

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_apply, i) for i in range(n)]
        for f in as_completed(futures):
            f.result()

    tags = rg.get_tags(Arn=arn)["Tags"]
    for key, value in expected.items():
        assert tags.get(key) == value, f"missing or wrong value for concurrently-written key {key}: {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
