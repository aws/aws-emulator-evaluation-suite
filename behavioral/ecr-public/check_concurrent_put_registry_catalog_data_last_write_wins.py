"""concurrent-put-registry-catalog-data-last-write-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-registry-catalog-data-last-write-wins"
GROUP = "concurrency"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """Two overlapping PutRegistryCatalogData calls with different displayName payloads
    resolve to exactly ONE of the two complete values -- never an interleaved/partial
    merge of the two strings and never an empty/corrupted result."""
    ecrp = ctx.client("ecr-public", region="us-east-1")

    baseline = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName", "")
    ctx.on_cleanup(lambda: ecrp.put_registry_catalog_data(displayName=baseline))

    name_a = ctx.unique_name("sim2real-behav-a-")[:100]
    name_b = ctx.unique_name("sim2real-behav-b-")[:100]
    assert name_a != name_b, f"racer payloads must differ to detect a merge/interleave: {name_a!r} == {name_b!r}"

    def _write(name: str) -> None:
        ecrp.put_registry_catalog_data(displayName=name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_write, name_a), pool.submit(_write, name_b)]
        for fut in futures:
            fut.result()

    final = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName")
    assert final in (name_a, name_b), (
        f"expected the final displayName to be exactly one of the two racing writes, "
        f"got a corrupted/merged value: {final!r}"
    )

    # A follow-up read must agree with the value already observed -- the resolved
    # state is stable, not still settling/flickering between the two payloads.
    reread = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName")
    assert reread == final, f"displayName is not stable across reads: {final!r} vs {reread!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
