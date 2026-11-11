"""optimize-waypoints-origin-only-minimal-success."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "optimize-waypoints-origin-only-minimal-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3344, 47.6015]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizeWaypoints with only an Origin is rejected with ValidationException and its exact message, while
    Origin plus Destination returns the order [Origin, Destination] with one Connection.
    """
    client = ctx.client("geo-routes")

    error = _client_error(lambda: client.optimize_waypoints(Origin=ORIGIN))
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for Origin-only, got {error!r}"
    )
    assert error["Message"] == "At least one of the following fields must be set: Destination, Waypoints.", (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.optimize_waypoints(Origin=ORIGIN, Destination=DESTINATION)
    optimized_ids = [wp["Id"] for wp in resp["OptimizedWaypoints"]]
    assert optimized_ids == ["Origin", "Destination"], (
        "Origin+Destination with no intermediate waypoints must produce the two-node chain "
        f"[Origin, Destination], got {optimized_ids!r}"
    )
    assert len(resp["Connections"]) == 1, (
        "a two-node chain must degenerate to a single direct hop, "
        f"got {resp['Connections']!r}"
    )
    assert resp["ImpedingWaypoints"] == [], f"expected no impeding waypoints, got {resp['ImpedingWaypoints']!r}"
    assert resp["Distance"] > 0, f"expected positive Distance, got {resp['Distance']!r}"
    assert resp["Duration"] > 0, f"expected positive Duration, got {resp['Duration']!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

