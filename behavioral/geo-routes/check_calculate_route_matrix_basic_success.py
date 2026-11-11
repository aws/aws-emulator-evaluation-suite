"""calculate-route-matrix-basic-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-basic-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# Two Seattle-area origins and two well-connected destinations.
_ORIGINS = [
    {"Position": [-122.3321, 47.6062]},  # Downtown Seattle
    {"Position": [-122.1963, 47.6101]},  # Bellevue
]
_DESTINATIONS = [
    {"Position": [-122.3088, 47.4502]},  # SeaTac Airport
    {"Position": [-122.4443, 47.2529]},  # Tacoma
]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix returns one row per Origin, one entry per Destination in
    each row, with real positive Distance/Duration for every well-connected pair and
    zero errors."""
    client = ctx.client("geo-routes")
    resp = client.calculate_route_matrix(Origins=_ORIGINS, Destinations=_DESTINATIONS)

    matrix = resp["RouteMatrix"]
    assert len(matrix) == len(_ORIGINS), (
        f"expected {len(_ORIGINS)} RouteMatrix rows (one per origin), got {len(matrix)}: {matrix!r}"
    )
    for row in matrix:
        assert len(row) == len(_DESTINATIONS), (
            f"expected {len(_DESTINATIONS)} entries per row (one per destination), "
            f"got {len(row)}: {row!r}"
        )
        for entry in row:
            assert "Error" not in entry, f"unexpected per-entry error: {entry}"
            assert entry["Distance"] > 0, f"expected Distance > 0, got {entry['Distance']!r}"
            assert entry["Duration"] > 0, f"expected Duration > 0, got {entry['Duration']!r}"
    assert resp["ErrorCount"] == 0, f"expected ErrorCount == 0, got {resp['ErrorCount']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
