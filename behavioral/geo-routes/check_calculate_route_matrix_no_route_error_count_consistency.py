"""calculate-route-matrix-no-route-error-count-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-no-route-error-count-consistency"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_HONOLULU = [-157.8583, 21.3069]
_PORTLAND = [-122.6784, 45.5152]
_SAN_FRANCISCO = [-122.4194, 37.7749]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a 2 x 2 Car route matrix with a Honolulu origin, every Honolulu entry carries Error NoRoute, the
    mainland entries have a positive Distance and Duration, and ErrorCount equals the 2 erroring entries.
    """
    client = ctx.client("geo-routes")
    resp = client.calculate_route_matrix(
        Origins=[{"Position": _SEATTLE}, {"Position": _HONOLULU}],
        Destinations=[{"Position": _PORTLAND}, {"Position": _SAN_FRANCISCO}],
        TravelMode="Car",
    )
    matrix = resp["RouteMatrix"]
    assert len(matrix) == 2 and all(len(row) == 2 for row in matrix), (
        f"expected a 2x2 RouteMatrix, got {matrix!r}"
    )

    mainland_row = matrix[0]  # Seattle -> {Portland, San Francisco}
    for entry in mainland_row:
        assert "Error" not in entry, f"expected no Error for a mainland pair, got {entry!r}"
        assert entry["Distance"] > 0, f"expected Distance > 0, got {entry['Distance']!r}"
        assert entry["Duration"] > 0, f"expected Duration > 0, got {entry['Duration']!r}"

    honolulu_row = matrix[1]  # Honolulu -> {Portland, San Francisco}
    for entry in honolulu_row:
        assert entry.get("Error") == "NoRoute", (
            f"expected Error=NoRoute for a Honolulu-origin car pair, got entry={entry!r}"
        )

    error_entries = sum(1 for row in matrix for entry in row if "Error" in entry)
    assert error_entries == 2, f"expected exactly 2 per-entry errors, counted {error_entries}"
    assert resp["ErrorCount"] == error_entries, (
        f"expected ErrorCount to equal the counted per-entry errors "
        f"({error_entries}), got ErrorCount={resp['ErrorCount']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
