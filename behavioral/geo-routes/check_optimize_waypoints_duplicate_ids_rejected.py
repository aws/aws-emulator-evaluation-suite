"""optimize-waypoints-duplicate-ids-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "optimize-waypoints-duplicate-ids-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected ValidationException for duplicate waypoint Ids, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two Waypoints sharing the same Id are rejected with ValidationException (Ids
    must be unique per request so Connections/ImpedingWaypoints can unambiguously
    reference them), while the identical request with distinct Ids succeeds."""
    client = ctx.client("geo-routes")
    duplicate_waypoints = [
        {"Id": "dup", "Position": [-122.3493, 47.6205]},
        {"Id": "dup", "Position": [-122.3320, 47.5990]},
    ]

    error = _client_error(
        lambda: client.optimize_waypoints(Origin=_ORIGIN, Waypoints=duplicate_waypoints)
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "'Id' must be unique across 'OriginOptions', 'Waypoints' and 'DestinationOptions'."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the identical request with unique Ids succeeds.
    distinct_waypoints = [
        {"Id": "wp-a", "Position": [-122.3493, 47.6205]},
        {"Id": "wp-b", "Position": [-122.3320, 47.5990]},
    ]
    resp = client.optimize_waypoints(Origin=_ORIGIN, Waypoints=distinct_waypoints)
    assert resp["Distance"] > 0, f"expected a positive Distance for distinct Ids, got {resp.get('Distance')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
