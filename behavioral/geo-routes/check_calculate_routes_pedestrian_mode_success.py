"""calculate-routes-pedestrian-mode-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-pedestrian-mode-success"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]
_PIKE_PLACE = [-122.3421, 47.6101]
# ~1km: loose enough for street-network snapping, tight enough that a
# reversed leg or a position in the wrong part of the city still fails it.
_SNAP_TOLERANCE_DEG = 0.01


def _assert_snapped_near(actual_position, expected_position, label):
    dlon = abs(actual_position[0] - expected_position[0])
    dlat = abs(actual_position[1] - expected_position[1])
    assert dlon < _SNAP_TOLERANCE_DEG and dlat < _SNAP_TOLERANCE_DEG, (
        f"{label} snapped Position {actual_position!r} is not within "
        f"{_SNAP_TOLERANCE_DEG} deg of the requested {expected_position!r}"
    )


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes with TravelMode Pedestrian returns Pedestrian legs whose travel steps sum to the leg's
    distance and duration, with Departure and Arrival snapped near the requested Origin and Destination.
    """
    client = ctx.client("geo-routes")
    resp = client.calculate_routes(
        Origin=_SPACE_NEEDLE,
        Destination=_PIKE_PLACE,
        TravelMode="Pedestrian",
    )
    routes = resp["Routes"]
    assert len(routes) >= 1, f"expected at least one route, got {routes!r}"
    route = routes[0]
    legs = route["Legs"]
    assert len(legs) >= 1, f"expected at least one leg, got {legs!r}"
    for leg in legs:
        assert leg["TravelMode"] == "Pedestrian", (
            f"expected TravelMode=Pedestrian, got {leg['TravelMode']!r}"
        )
        assert leg["Type"] == "Pedestrian", f"expected Type=Pedestrian, got {leg['Type']!r}"
        details = leg["PedestrianLegDetails"]
        travel_steps = details["TravelSteps"]
        assert len(travel_steps) >= 1, f"expected at least one travel step, got {travel_steps!r}"

        # Depart/Arrive bookend steps legitimately carry zero distance/duration,
        # so assert on the leg's totals rather than on every individual step.
        total_distance = sum(step["Distance"] for step in travel_steps)
        total_duration = sum(step["Duration"] for step in travel_steps)
        assert total_distance > 0, (
            f"expected a nonzero walking distance, summed TravelSteps to {total_distance}m"
        )
        assert total_duration > 0, (
            f"expected a nonzero walking duration, summed TravelSteps to {total_duration}s"
        )

        # PedestrianLegDetails.Summary is documented optional; when present its
        # own totals must agree with the TravelSteps that make it up, tying two
        # independently-reported numbers together rather than trusting either alone.
        summary = details.get("Summary")
        if summary is not None:
            travel_only = summary.get("TravelOnly")
            if travel_only is not None and "Duration" in travel_only:
                assert travel_only["Duration"] == total_duration, (
                    f"Summary.TravelOnly.Duration {travel_only['Duration']} does not match "
                    f"the sum of TravelSteps durations {total_duration}"
                )
            overview = summary.get("Overview")
            if overview is not None and "Distance" in overview:
                assert overview["Distance"] == total_distance, (
                    f"Summary.Overview.Distance {overview['Distance']} does not match "
                    f"the sum of TravelSteps distances {total_distance}"
                )
                assert 0 < overview["Distance"] < 5_000, (
                    f"expected Overview.Distance in (0, 5000)m for the ~1.5km Space Needle -> "
                    f"Pike Place walk, got {overview['Distance']}"
                )

        arrival_position = details["Arrival"]["Place"]["Position"]
        departure_position = details["Departure"]["Place"]["Position"]
        _assert_snapped_near(departure_position, _SPACE_NEEDLE, "Departure")
        _assert_snapped_near(arrival_position, _PIKE_PLACE, "Arrival")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
