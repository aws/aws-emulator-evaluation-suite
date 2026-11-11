"""concurrent-list-calls-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-list-calls-consistent"
GROUP = "concurrency"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ListRecommendedActions calls all succeed and observe the same id set (no cross-request corruption)."""
    client = ctx.client("bcm-recommended-actions")

    def _call(_):
        resp = client.list_recommended_actions()
        return frozenset(a["id"] for a in resp["recommendedActions"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    assert len(results) == 8, f"expected 8 concurrent results, got {len(results)}"
    first = results[0]
    for other in results[1:]:
        assert other == first, "concurrent reads observed different result sets"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
