"""concurrent-identical-route-requests-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-identical-route-requests-consistent"
GROUP = "concurrency"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_DESTINATIONS = {
    "portland": [-122.6784, 45.5152],
    "tacoma": [-122.4443, 47.2529],
    "bellevue": [-122.2015, 47.6101],
    "everett": [-122.2021, 47.9790],
}
_DEPARTURE_TIME = "2030-06-15T09:00:00Z"
_REPEATS = 2


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent CalculateRoutes calls to several destinations each return the Distance a sequential call to
    their own destination returns, never another racer's.
    """
    client = ctx.client("geo-routes")

    def _distance_for(destination):
        resp = client.calculate_routes(
            Origin=_SEATTLE,
            Destination=destination,
            TravelMode="Car",
            DepartureTime=_DEPARTURE_TIME,
        )
        return resp["Routes"][0]["Summary"]["Distance"]

    baseline = {name: _distance_for(dest) for name, dest in _DESTINATIONS.items()}
    assert all(d > 0 for d in baseline.values()), f"non-positive baseline distance: {baseline!r}"
    assert len(set(baseline.values())) == len(baseline), (
        "chosen destinations must yield mutually distinct distances, or a cross-delivered "
        f"response would be undetectable; got {baseline!r}"
    )

    racers = list(_DESTINATIONS.items()) * _REPEATS

    def _race(item):
        name, dest = item
        return name, _distance_for(dest)

    with ThreadPoolExecutor(max_workers=len(racers)) as pool:
        results = list(pool.map(_race, racers))

    assert len(results) == len(racers), (
        f"expected {len(racers)} concurrent responses, got {len(results)}: {results!r}"
    )
    mismatches = [
        (name, got, baseline[name]) for name, got in results if got != baseline[name]
    ]
    assert not mismatches, (
        f"cross-contaminated concurrent responses (name, got, expected): {mismatches}; "
        f"full baseline={baseline!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
