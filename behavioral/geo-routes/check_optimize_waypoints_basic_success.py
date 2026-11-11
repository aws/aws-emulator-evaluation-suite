"""optimize-waypoints-basic-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "optimize-waypoints-basic-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_WAYPOINTS = [
    {"Id": "space-needle", "Position": [-122.3493, 47.6205]},
    {"Id": "pioneer-square", "Position": [-122.3320, 47.5990]},
]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizeWaypoints lists Origin first and each waypoint once at its requested Position, chains
    Connections along that order, and reports a Distance and Duration equal to the sums of its per-hop values.
    """
    client = ctx.client("geo-routes")
    resp = client.optimize_waypoints(Origin=_ORIGIN, Waypoints=_WAYPOINTS)

    optimized_ids = [wp["Id"] for wp in resp["OptimizedWaypoints"]]
    input_ids = {wp["Id"] for wp in _WAYPOINTS}
    assert optimized_ids[0] == "Origin", f"expected Origin first, got {optimized_ids}"
    # Every requested waypoint appears exactly once among the optimized results.
    assert input_ids.issubset(set(optimized_ids)), f"missing waypoints: {input_ids - set(optimized_ids)}"
    assert len(optimized_ids) == len(set(optimized_ids)), f"duplicate ids in {optimized_ids}"
    for waypoint_id in input_ids:
        count = optimized_ids.count(waypoint_id)
        assert count == 1, f"{waypoint_id} appears {count} times in {optimized_ids}"

    # Each node's Position is the exact one it was requested with, not a
    # snapped/rounded/fabricated stand-in.
    input_positions = {"Origin": _ORIGIN, **{wp["Id"]: wp["Position"] for wp in _WAYPOINTS}}
    for wp in resp["OptimizedWaypoints"]:
        expected = input_positions[wp["Id"]]
        assert wp["Position"] == expected, f"{wp['Id']}: expected Position {expected}, got {wp['Position']}"

    connections = resp["Connections"]
    # A chain of len(OptimizedWaypoints) nodes has exactly len-1 hops, and those
    # hops must chain From/To across the sequence AWS itself just reported --
    # not merely count right.
    assert len(connections) == len(optimized_ids) - 1, (
        f"expected {len(optimized_ids) - 1} connections for {optimized_ids}, got {len(connections)}"
    )
    expected_hops = list(zip(optimized_ids[:-1], optimized_ids[1:]))
    actual_hops = [(c["From"], c["To"]) for c in connections]
    assert actual_hops == expected_hops, f"connections {actual_hops} do not chain sequence {expected_hops}"
    for connection in connections:
        assert connection["TravelDuration"] >= 0, connection
        assert connection["Distance"] >= 0, connection

    # The reported aggregate is exactly the sum of the per-hop values in the
    # same response -- a fabricated total that merely happens to be positive
    # would fail here even though the earlier bare `> 0` checks would not.
    assert resp["Distance"] == sum(c["Distance"] for c in connections), (
        f"Distance {resp['Distance']} != sum of connection distances "
        f"{sum(c['Distance'] for c in connections)}"
    )
    hop_duration = sum(c["TravelDuration"] + c["WaitDuration"] + c["RestDuration"] for c in connections)
    assert resp["Duration"] == hop_duration, f"Duration {resp['Duration']} != summed hop duration {hop_duration}"
    tb = resp["TimeBreakdown"]
    tb_total = tb["TravelDuration"] + tb["WaitDuration"] + tb["RestDuration"] + tb["ServiceDuration"]
    assert resp["Duration"] == tb_total, f"Duration {resp['Duration']} != TimeBreakdown total {tb_total}"

    assert resp["Distance"] > 0, resp["Distance"]
    assert resp["Duration"] > 0, resp["Duration"]
    assert resp["ImpedingWaypoints"] == [], resp["ImpedingWaypoints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
