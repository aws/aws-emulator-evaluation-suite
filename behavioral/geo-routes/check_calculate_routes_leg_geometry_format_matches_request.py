"""calculate-routes-leg-geometry-format-matches-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-leg-geometry-format-matches-request"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]
_PIKE_PLACE = [-122.3421, 47.6101]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """LegGeometryFormat controls whether leg geometry is returned as a
    LineString (Simple, the default) or an encoded Polyline (FlexiblePolyline) -
    the two are mutually exclusive and must match what was requested."""
    client = ctx.client("geo-routes")

    simple_resp = client.calculate_routes(
        Origin=_SPACE_NEEDLE,
        Destination=_PIKE_PLACE,
        TravelMode="Pedestrian",
        LegGeometryFormat="Simple",
    )
    assert simple_resp["LegGeometryFormat"] == "Simple", (
        f"echoed LegGeometryFormat: expected Simple, got {simple_resp['LegGeometryFormat']!r}"
    )
    simple_geometry = simple_resp["Routes"][0]["Legs"][0]["Geometry"]
    assert "LineString" in simple_geometry, f"expected LineString key, got keys {list(simple_geometry)}"
    assert "Polyline" not in simple_geometry, f"Simple format must not also carry Polyline, got keys {list(simple_geometry)}"
    simple_line = simple_geometry["LineString"]
    assert len(simple_line) >= 2, f"expected a LineString with >=2 points, got {len(simple_line)}"
    for point in simple_line:
        assert len(point) == 2, f"expected [lon, lat] pairs, got point {point!r}"

    flexible_resp = client.calculate_routes(
        Origin=_SPACE_NEEDLE,
        Destination=_PIKE_PLACE,
        TravelMode="Pedestrian",
        LegGeometryFormat="FlexiblePolyline",
    )
    assert flexible_resp["LegGeometryFormat"] == "FlexiblePolyline", (
        f"echoed LegGeometryFormat: expected FlexiblePolyline, got {flexible_resp['LegGeometryFormat']!r}"
    )
    flexible_geometry = flexible_resp["Routes"][0]["Legs"][0]["Geometry"]
    assert "Polyline" in flexible_geometry, f"expected Polyline key, got keys {list(flexible_geometry)}"
    assert "LineString" not in flexible_geometry, f"FlexiblePolyline format must not also carry LineString, got keys {list(flexible_geometry)}"
    polyline = flexible_geometry["Polyline"]
    assert isinstance(polyline, str), f"expected an encoded polyline string, got {type(polyline)}"
    assert len(polyline) > 0, "expected a non-empty encoded polyline string"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
