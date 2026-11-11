"""snap-to-roads-snap-radius-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snap-to-roads-snap-radius-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_P1 = [-122.3421, 47.6101]
_P2 = [-122.3428, 47.6110]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapRadius is bounded to [0,10000] meters; 10001 is rejected with
    ValidationException while the boundary value 10000 (positive control) is
    accepted."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.snap_to_roads(
            TracePoints=[{"Position": _P1}, {"Position": _P2}],
            TravelMode="Car",
            SnapRadius=10001,
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == "'SnapRadius' must not be greater than 10000", (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.snap_to_roads(
        TracePoints=[{"Position": _P1}, {"Position": _P2}],
        TravelMode="Car",
        SnapRadius=10000,
    )
    snapped = resp["SnappedTracePoints"]
    assert len(snapped) == 2, f"expected 2 SnappedTracePoints for the boundary value, got {len(snapped)}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects SnapRadius=10001, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
