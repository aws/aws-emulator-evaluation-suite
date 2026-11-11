"""concurrent-put-repository-catalog-data-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-repository-catalog-data-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["ecr-public"]

_FIELDS = ("description", "architectures", "operatingSystems", "aboutText", "usageText")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutRepositoryCatalogData calls with different payloads resolve
    deterministically to exactly one complete, uncorrupted record -- last-writer-wins, never
    a field-by-field interleaving of both payloads."""
    ecrpublic = _ecrpublic(ctx)
    name = ctx.unique_name("sim2real-behav-ecrpub-cc-")
    ecrpublic.create_repository(
        repositoryName=name,
        tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=name, force=True))

    payload_a = {
        "description": "sim2real racer A description",
        "architectures": ["ARM"],
        "operatingSystems": ["Linux"],
        "aboutText": "about-A",
        "usageText": "usage-A",
    }
    payload_b = {
        "description": "sim2real racer B description",
        "architectures": ["ARM 64"],
        "operatingSystems": ["Windows"],
        "aboutText": "about-B",
        "usageText": "usage-B",
    }

    def _put(payload):
        return ecrpublic.put_repository_catalog_data(repositoryName=name, catalogData=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, payload_a), pool.submit(_put, payload_b)]
        for f in futures:
            f.result()

    actual = ecrpublic.get_repository_catalog_data(repositoryName=name)["catalogData"]
    actual_subset = {k: actual.get(k) for k in _FIELDS}

    matches_a = actual_subset == payload_a
    matches_b = actual_subset == payload_b
    assert matches_a or matches_b, f"catalog record is neither pure A nor pure B: {actual_subset}"
    # Exactly one writer's full payload won -- never a merge of some fields from A and some
    # from B, which would fail both equality checks above; never both flags true, either
    # (payload_a != payload_b, so that combination is impossible by construction, but this
    # keeps the invariant explicit).
    assert matches_a != matches_b, (
        f"expected exactly one racer to win outright, got matches_a={matches_a} "
        f"matches_b={matches_b} for record {actual_subset}"
    )

    # Stable afterwards: a second read shows the identical winning record, no oscillation
    # between racers on subsequent reads.
    again = ecrpublic.get_repository_catalog_data(repositoryName=name)["catalogData"]
    again_subset = {k: again.get(k) for k in _FIELDS}
    assert again_subset == actual_subset, (
        f"catalog record is not stable across reads: first read {actual_subset}, "
        f"second read {again_subset}"
    )


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client is pinned
    there through `ctx.client(..., region=)`."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
