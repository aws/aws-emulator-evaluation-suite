"""calculate-isolines-distance-thresholds-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-distance-thresholds-success"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines with distance-based thresholds returns one isoline per
    threshold, each tagged with its own DistanceThreshold and non-empty
    geometry (rather than a TimeThreshold)."""
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Origin=_SPACE_NEEDLE,
        TravelMode="Pedestrian",
        Thresholds={"Distance": [1000, 2000]},
    )
    isolines = resp["Isolines"]
    assert len(isolines) == 2, f"expected 2 isolines, got {len(isolines)}: {isolines}"
    thresholds_seen = {isoline["DistanceThreshold"] for isoline in isolines}
    assert thresholds_seen == {1000, 2000}, f"expected thresholds {{1000, 2000}}, got {thresholds_seen}"
    by_threshold = {isoline["DistanceThreshold"]: isoline for isoline in isolines}
    for isoline in isolines:
        # Distance-based isolines are tagged with DistanceThreshold only;
        # TimeThreshold is absent (not zero) since no time threshold was requested.
        assert "TimeThreshold" not in isoline, f"expected no TimeThreshold on a distance-based isoline, got {isoline.get('TimeThreshold')}"
        assert len(isoline["Geometries"]) >= 1, f"expected non-empty Geometries, got {isoline['Geometries']}"
        geometry = isoline["Geometries"][0]
        # IsolineGeometryFormat was not requested, so the modeled default (FlexiblePolyline)
        # applies: geometry must arrive as an encoded PolylinePolygon, not a Polygon ring list.
        assert "PolylinePolygon" in geometry, f"expected default FlexiblePolyline format (PolylinePolygon), got keys {sorted(geometry)}"
        assert "Polygon" not in geometry, f"Polygon and PolylinePolygon are mutually exclusive, got both: {geometry}"
        assert len(geometry["PolylinePolygon"]) >= 1 and len(geometry["PolylinePolygon"][0]) > 0, (
            f"expected a non-empty encoded polyline ring, got {geometry['PolylinePolygon']}"
        )
    # Distinct thresholds must produce distinct reachable-area geometry, not the same
    # shape copy-pasted under two different DistanceThreshold labels.
    assert by_threshold[1000]["Geometries"] != by_threshold[2000]["Geometries"], (
        "1000m and 2000m distance thresholds produced identical isoline geometry"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
