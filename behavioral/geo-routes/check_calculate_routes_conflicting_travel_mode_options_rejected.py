"""calculate-routes-conflicting-travel-mode-options-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-conflicting-travel-mode-options-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]
_DESTINATION = [-122.3493, 47.6205]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes with TravelMode Car and Truck-only TravelModeOptions is rejected with
    ValidationException and its exact message, while the same request without those options returns a route.
    """
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_routes(
            Origin=_ORIGIN,
            Destination=_DESTINATION,
            TravelMode="Car",
            TravelModeOptions={"Truck": {"GrossWeight": 10000}},
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Only the following fields may be set within 'TravelModeOptions' when "
        "'TravelMode' has value Car: 'Car', 'Ev'."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the identical request minus the conflicting options succeeds.
    resp = client.calculate_routes(Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car")
    assert len(resp["Routes"]) >= 1, f"expected at least one route, got {resp['Routes']!r}"
    distance = resp["Routes"][0]["Summary"]["Distance"]
    assert distance > 0, f"expected positive route distance, got {distance!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
