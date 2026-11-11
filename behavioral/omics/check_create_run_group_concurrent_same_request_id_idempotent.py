"""create-run-group-concurrent-same-request-id-idempotent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-run-group-concurrent-same-request-id-idempotent"
GROUP = "concurrency"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racers calling CreateRunGroup with the same requestId and identical params all resolve to one run group."""
    omics = ctx.client("omics")
    request_id = ctx.unique_name("sim2real-rgraces-")
    name = ctx.unique_name("sim2real-rungroup-race-")
    racer_count = 8

    def _race(_i: int):
        return omics.create_run_group(
            requestId=request_id, name=name, maxCpus=7, tags={"sim2real": "true"}
        )

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    ids = {r["id"] for r in results}
    assert len(ids) == 1, f"racers with an identical requestId produced distinct run group ids: {ids!r}"
    group_id = ids.pop()
    ctx.on_cleanup(lambda: omics.delete_run_group(id=group_id))

    listed = [g["id"] for g in omics.list_run_groups(name=name)["items"] if g["id"] == group_id]
    assert len(listed) == 1, f"expected exactly one run group named {name!r}, found {len(listed)}"

    described = omics.get_run_group(id=group_id)
    assert described["maxCpus"] == 7, (
        f"expected maxCpus=7 on the deduplicated run group, got {described.get('maxCpus')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
