"""calculate-routes-concurrent-requests-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "calculate-routes-concurrent-requests-consistent"
GROUP = "concurrency"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_DESTINATION = [-122.3493, 47.6205]  # Space Needle
_CONCURRENCY = 8


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Identical CalculateRoutes requests sent concurrently all return the same positive Distance and
    Duration.
    """
    client = ctx.client("geo-routes")

    def _one_call(_: int):
        resp = client.calculate_routes(
            Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car"
        )
        summary = resp["Routes"][0]["Summary"]
        return (summary["Distance"], summary["Duration"])

    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        results = list(pool.map(_one_call, range(_CONCURRENCY)))

    assert len(results) == _CONCURRENCY, (
        f"expected {_CONCURRENCY} completed calls, got {len(results)}"
    )
    distinct_results = set(results)
    assert len(distinct_results) == 1, (
        f"expected identical concurrent responses for a deterministic request, got {distinct_results}"
    )
    distance, duration = next(iter(distinct_results))
    assert distance > 0 and duration > 0, (
        f"expected positive distance and duration, got distance={distance}, duration={duration}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
