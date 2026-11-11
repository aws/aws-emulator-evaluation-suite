"""calculate-routes-leg-geometry-simple-format."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-leg-geometry-simple-format"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]
_DESTINATION = [-122.3493, 47.6205]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Requesting LegGeometryFormat=Simple yields decoded [lon, lat] LineString
    coordinates (not a still-encoded polyline string) that trace a real path between
    Origin and Destination."""
    client = ctx.client("geo-routes")
    resp = client.calculate_routes(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        LegGeometryFormat="Simple",
    )
    assert resp["LegGeometryFormat"] == "Simple", f"expected Simple, got {resp.get('LegGeometryFormat')}"
    leg = resp["Routes"][0]["Legs"][0]
    geometry = leg["Geometry"]
    assert "Polyline" not in geometry, f"Simple format must not carry an encoded Polyline, got keys {list(geometry)}"
    line = geometry["LineString"]
    # A driving route over ~1.5km of city streets is a real polyline, not just its two
    # endpoints; a target that merely echoes Origin/Destination as a 2-point line would
    # pass a bare len(line) >= 2 check. AWS returns a LineString of dozens of points for
    # this ~1.5km route, so >5 leaves generous margin while still requiring
    # an actually-decoded, multi-vertex path.
    assert len(line) > 5, f"expected a decoded multi-point route, got {len(line)} point(s): {line}"
    first_point = line[0]
    last_point = line[-1]
    assert len(first_point) == 2 and len(last_point) == 2, (
        f"expected [lon, lat] pairs, got first={first_point} last={last_point}"
    )
    # The decoded path should start near the requested Origin and end near Destination.
    assert abs(first_point[0] - _ORIGIN[0]) < 0.02 and abs(first_point[1] - _ORIGIN[1]) < 0.02, (
        f"first point {first_point} not near Origin {_ORIGIN}"
    )
    assert abs(last_point[0] - _DESTINATION[0]) < 0.02 and abs(last_point[1] - _DESTINATION[1]) < 0.02, (
        f"last point {last_point} not near Destination {_DESTINATION}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
