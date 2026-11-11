"""calculate-isolines-time-thresholds-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-time-thresholds-success"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines with two time thresholds returns exactly one isoline
    per threshold, each carrying its own TimeThreshold and non-empty polygon
    geometry."""
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Origin=_SPACE_NEEDLE,
        TravelMode="Pedestrian",
        Thresholds={"Time": [300, 600]},
        IsolineGeometryFormat="Simple",
    )
    assert resp["IsolineGeometryFormat"] == "Simple", (
        f"expected echoed IsolineGeometryFormat 'Simple', got {resp['IsolineGeometryFormat']!r}"
    )
    isolines = resp["Isolines"]
    assert len(isolines) == 2, f"expected one isoline per threshold (2), got {len(isolines)}"
    thresholds_seen = {isoline["TimeThreshold"] for isoline in isolines}
    assert thresholds_seen == {300, 600}, (
        f"expected TimeThreshold set {{300, 600}}, got {thresholds_seen}"
    )
    for isoline in isolines:
        geometries = isoline["Geometries"]
        assert len(geometries) >= 1, (
            f"expected non-empty Geometries for TimeThreshold={isoline['TimeThreshold']}, got 0"
        )
        assert "Polygon" in geometries[0], (
            f"expected 'Polygon' key in Geometries[0] for Simple format, "
            f"got keys {list(geometries[0].keys())}"
        )
        assert "PolylinePolygon" not in geometries[0], (
            f"expected no 'PolylinePolygon' key when IsolineGeometryFormat='Simple', "
            f"got keys {list(geometries[0].keys())}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
