"""snap-to-roads-too-few-points-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snap-to-roads-too-few-points-rejected"
GROUP = "error-semantics"
SERVICES = ["geo-routes"]

_P1 = [-122.3421, 47.6101]
_P2 = [-122.3428, 47.6110]
# Longitude outside [-180, 180] with a valid latitude: botocore has no client-side range check on Position,
# so the service itself rejects it. The TracePoints minimum of 2 is enforced client-side by botocore and
# never reaches the service.
_MALFORMED_POSITION = [200.0, 47.6110]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads with a trace point whose longitude is out of range is rejected with ValidationException and
    its exact message, while a request of 2 well-formed points returns 2 snapped points.
    """
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.snap_to_roads(
            TracePoints=[{"Position": _P1}, {"Position": _MALFORMED_POSITION}],
            TravelMode="Car",
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Longitude must be between -180 and 180 degrees, but was set to 200."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.snap_to_roads(
        TracePoints=[{"Position": _P1}, {"Position": _P2}], TravelMode="Car"
    )
    assert len(resp["SnappedTracePoints"]) == 2


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

