"""calculate-routes-missing-destination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-missing-destination-rejected"
GROUP = "error-semantics"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]
_PIKE_PLACE = [-122.3421, 47.6101]
# Longitude/latitude out of the valid [-180,180]/[-90,90] range: botocore has no
# client-side range check on Position (just a fixed-length [lon,lat] pair), so
# this malformed Position is rejected server-side, not by the SDK.
_MALFORMED_POSITION = [200.0, 100.0]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes rejects a Destination Position with out-of-range
    longitude/latitude with ValidationException, while the equivalent request
    with a valid Destination (positive control) succeeds."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_routes(
            Origin=_SPACE_NEEDLE, Destination=_MALFORMED_POSITION, TravelMode="Car"
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Longitude must be between -180 and 180 degrees, but was set to 200."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.calculate_routes(
        Origin=_SPACE_NEEDLE,
        Destination=_PIKE_PLACE,
        TravelMode="Car",
    )
    assert len(resp["Routes"]) >= 1, f"positive control returned no routes: {resp!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

