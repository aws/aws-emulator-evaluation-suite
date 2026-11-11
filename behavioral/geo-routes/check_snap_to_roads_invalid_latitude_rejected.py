"""snap-to-roads-invalid-latitude-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snap-to-roads-invalid-latitude-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected snap_to_roads to reject the malformed latitude, but it "
        f"succeeded and returned {result!r}"
    )


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads with a trace point at latitude 200 is rejected with ValidationException and its exact
    message, while the same request with a valid latitude returns 2 snapped points.
    """
    client = ctx.client("geo-routes")
    malformed_points = [
        {"Position": [-122.3366, 47.6101]},
        {"Position": [-122.3363, 200.0]},  # invalid latitude
    ]

    error = _client_error(lambda: client.snap_to_roads(TracePoints=malformed_points))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Latitude must be between -90 and 90 degrees, but was set to 200."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the identical request with a valid latitude succeeds.
    valid_points = [
        {"Position": [-122.3366, 47.6101]},
        {"Position": [-122.3363, 47.6111]},
    ]
    resp = client.snap_to_roads(TracePoints=valid_points)
    assert len(resp["SnappedTracePoints"]) == 2, (
        f"expected 2 snapped points for the valid-latitude control, got "
        f"{len(resp['SnappedTracePoints'])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
