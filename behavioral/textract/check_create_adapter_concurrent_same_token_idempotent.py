"""create-adapter-concurrent-same-token-idempotent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "create-adapter-concurrent-same-token-idempotent"
GROUP = "concurrency"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateAdapter calls that share the same ClientRequestToken and identical
    parameters must all resolve to exactly one AdapterId -- the idempotency contract holds under
    contention, it isn't just a lucky sequential-only behavior."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    token = ctx.unique_name("sim2real-token-")
    racers = 8

    def _create():
        return textract.create_adapter(
            AdapterName=name,
            FeatureTypes=["QUERIES"],
            ClientRequestToken=token,
            Tags={"env": "sim2real", "purpose": "fidelity-check"},
        )["AdapterId"]

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_create) for _ in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == racers, f"expected {racers} results, got {len(results)}"
    distinct_ids = set(results)
    assert len(distinct_ids) == 1, f"expected exactly 1 distinct AdapterId, got {distinct_ids!r}"
    adapter_id = distinct_ids.pop()
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    # Confirm only one adapter with this name actually exists server-side.
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = textract.list_adapters(**kwargs)
        matches += sum(1 for a in resp.get("Adapters", []) if a["AdapterName"] == name)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert matches == 1, f"expected exactly 1 adapter named {name!r} server-side, found {matches}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
