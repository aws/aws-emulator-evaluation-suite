"""concurrent-identical-calls-return-consistent-ids."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-identical-calls-return-consistent-ids"
GROUP = "concurrency"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Firing several identical ListRecommendedActions calls in parallel
    against the same account must never produce torn/inconsistent reads: all
    concurrent responses agree on exactly the same set of action ids."""
    client = ctx.client("bcm-recommended-actions")

    def _call(_: int) -> frozenset[str]:
        resp = client.list_recommended_actions(maxResults=1000)
        return frozenset(a["id"] for a in resp["recommendedActions"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    first = results[0]
    for i, result in enumerate(results[1:], start=1):
        assert result == first, f"call {i} saw {result}, call 0 saw {first}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
