"""calculate-route-matrix-empty-origins-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-route-matrix-empty-origins-rejected"
GROUP = "error-semantics"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]


def _grid(base, n, step=0.02):
    """n distinct positions offset from base so the service treats them as
    genuinely different origins/destinations."""
    lon, lat = base
    return [[lon + i * step, lat + i * step] for i in range(n)]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix with an Unbounded RoutingBoundary rejects an 11 x 10 matrix, above the 100-entry
    cap, with ValidationException and its exact message, while a 5 x 5 matrix returns 5 rows of 5 entries.
    """
    client = ctx.client("geo-routes")

    # 11 x 10 = 110 > 100 unbounded cap.
    origins_over = [{"Position": p} for p in _grid(_SEATTLE, 11)]
    destinations_over = [{"Position": p} for p in _grid([_SEATTLE[0] + 1, _SEATTLE[1] + 1], 10)]

    error = _client_error(
        lambda: client.calculate_route_matrix(
            Origins=origins_over,
            Destinations=destinations_over,
            TravelMode="Car",
            RoutingBoundary={"Unbounded": True},
        )
    )
    code = error.get("Code")
    assert code == "ValidationException", (
        f"expected ValidationException for an 11x10=110 matrix over the "
        f"Unbounded 100-pair cap, got {code!r} (error={error!r})"
    )
    assert error["Message"] == (
        "The total number of routes to calculate must be less than or equal to 100 "
        "when 'RoutingBoundary.Unbounded' has value true."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # 5 x 5 = 25 <= 100 unbounded cap -> succeeds (positive control).
    origins_ok = [{"Position": p} for p in _grid(_SEATTLE, 5)]
    destinations_ok = [{"Position": p} for p in _grid([_SEATTLE[0] + 1, _SEATTLE[1] + 1], 5)]
    resp = client.calculate_route_matrix(
        Origins=origins_ok,
        Destinations=destinations_ok,
        TravelMode="Car",
        RoutingBoundary={"Unbounded": True},
    )
    matrix = resp["RouteMatrix"]
    assert len(matrix) == 5, f"expected 5 origin rows in RouteMatrix, got {len(matrix)}"
    assert len(matrix[0]) == 5, (
        f"expected 5 destination entries in the first row, got {len(matrix[0])}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

