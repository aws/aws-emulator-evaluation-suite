"""optimize-waypoints-driving-distance-clustering-groups-nearby-waypoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "optimize-waypoints-driving-distance-clustering-groups-nearby-waypoints"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]  # Downtown Seattle
CLOSE_WAYPOINT_A = {"Id": "close-a", "Position": [-122.2015, 47.6101]}  # Bellevue
CLOSE_WAYPOINT_B = {"Id": "close-b", "Position": [-122.2005, 47.6111]}  # ~150m from A
FAR_WAYPOINT = {"Id": "far", "Position": [-122.1215, 47.6740]}  # Redmond, ~7km from A


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DrivingDistance clustering must group waypoints that are within the
    configured driving distance of each other into the same ClusterIndex, and
    keep a waypoint well outside that distance in a different cluster."""
    client = ctx.client("geo-routes")
    resp = client.optimize_waypoints(
        Origin=ORIGIN,
        Destination=FAR_WAYPOINT["Position"],
        Waypoints=[CLOSE_WAYPOINT_A, CLOSE_WAYPOINT_B, FAR_WAYPOINT],
        Clustering={
            "Algorithm": "DrivingDistance",
            "DrivingDistanceOptions": {"DrivingDistance": 5000},
        },
    )

    by_id = {wp["Id"]: wp for wp in resp["OptimizedWaypoints"] if "Id" in wp}
    assert {"close-a", "close-b", "far"} <= set(by_id), (
        f"expected close-a, close-b, far in response, got {sorted(by_id)}"
    )
    cluster_a = by_id["close-a"].get("ClusterIndex")
    cluster_b = by_id["close-b"].get("ClusterIndex")
    cluster_far = by_id["far"].get("ClusterIndex")
    # AWS always clusters this geometry (150m apart vs. a 5000m driving
    # distance, 7km for the outlier) and assigns a ClusterIndex, so a
    # response with no ClusterIndex at all is a target that never clustered,
    # not a legitimate alternate outcome for this input.
    assert cluster_a is not None and cluster_b is not None and cluster_far is not None, (
        f"expected ClusterIndex on every waypoint, got a={cluster_a} b={cluster_b} far={cluster_far}"
    )
    assert cluster_a == cluster_b, f"expected close-a and close-b in the same cluster, got {cluster_a} != {cluster_b}"
    assert cluster_a != cluster_far, f"expected far waypoint in a different cluster, got {cluster_a} == {cluster_far}"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
