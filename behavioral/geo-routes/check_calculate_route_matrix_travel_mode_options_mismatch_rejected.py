"""calculate-route-matrix-travel-mode-options-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-route-matrix-travel-mode-options-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix with Truck TravelModeOptions and TravelMode Pedestrian is rejected with
    ValidationException and its exact message, while the same options with TravelMode Truck route.
    """
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_route_matrix(
            Origins=[{"Position": ORIGIN}],
            Destinations=[{"Position": DESTINATION}],
            TravelMode="Pedestrian",
            TravelModeOptions={"Truck": {"GrossWeight": 10000}},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for Pedestrian mode with Truck-only options, "
        f"got {error.get('Code')!r}"
    )
    assert error["Message"] == (
        "'TravelModeOptions.Truck' must not be set when 'TravelMode' has value Pedestrian."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the Truck options paired with the matching travel mode.
    resp = client.calculate_route_matrix(
        Origins=[{"Position": ORIGIN}],
        Destinations=[{"Position": DESTINATION}],
        TravelMode="Truck",
        TravelModeOptions={"Truck": {"GrossWeight": 10000}},
    )
    entry = resp["RouteMatrix"][0][0]
    assert entry.get("Error") is None, (
        f"expected no Error for the matching Truck mode/Truck options call, got {entry.get('Error')!r}"
    )
    assert entry["Distance"] > 0, f"expected a positive Distance, got {entry['Distance']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
