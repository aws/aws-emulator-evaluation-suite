"""calculate-route-matrix-concurrent-identical-requests-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "calculate-route-matrix-concurrent-identical-requests-consistent"
GROUP = "concurrency"
SERVICES = ["geo-routes"]

ORIGINS = [{"Position": [-122.3410, 47.6089]}]
DESTINATIONS = [{"Position": [-122.3088, 47.4502]}]
CONCURRENCY = 8


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix, fired concurrently with identical inputs, must
    not let one racer's computation corrupt another's -- every racer gets the
    same entry distance for the same pair."""
    client = ctx.client("geo-routes")

    def _one_call(_: int) -> int:
        resp = client.calculate_route_matrix(Origins=ORIGINS, Destinations=DESTINATIONS)
        entry = resp["RouteMatrix"][0][0]
        assert entry.get("Error") is None, f"expected a routable entry, got Error={entry.get('Error')!r}"
        return entry["Distance"]

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        distances = list(pool.map(_one_call, range(CONCURRENCY)))

    assert len(distances) == CONCURRENCY, f"expected {CONCURRENCY} racer results, got {len(distances)}"
    assert all(d > 0 for d in distances), f"expected every racer to see a positive distance, got {distances}"
    assert len(set(distances)) == 1, (
        f"expected identical concurrent requests to agree on Distance, got {distances}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
