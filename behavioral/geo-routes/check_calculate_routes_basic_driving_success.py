"""calculate-routes-basic-driving-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-basic-driving-success"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes returns a drivable route with positive distance/duration
    and Simple-format (LineString) leg geometry by default."""
    client = ctx.client("geo-routes")
    resp = client.calculate_routes(
        Origin=_SEATTLE,
        Destination=_PORTLAND,
        TravelMode="Car",
        LegGeometryFormat="Simple",
    )
    assert resp["LegGeometryFormat"] == "Simple", (
        f"requested LegGeometryFormat=Simple, response echoed {resp['LegGeometryFormat']!r}"
    )
    routes = resp["Routes"]
    assert len(routes) >= 1, f"expected at least one route, got {routes!r}"
    route = routes[0]
    summary = route["Summary"]
    # Seattle -> Portland is roughly 280 km by road; allow a generous floor.
    assert summary["Distance"] > 200_000, (
        f"expected Seattle->Portland driving distance > 200,000m, got {summary['Distance']!r}"
    )
    assert summary["Duration"] > 0, f"expected positive Duration, got {summary['Duration']!r}"
    legs = route["Legs"]
    assert len(legs) >= 1, f"expected at least one leg, got {legs!r}"
    for leg in legs:
        assert leg["TravelMode"] == "Car", (
            f"requested TravelMode=Car, leg reported {leg['TravelMode']!r}"
        )
        geometry = leg["Geometry"]
        assert "LineString" in geometry, (
            f"Simple format requires LineString geometry, got keys {list(geometry)!r}"
        )
        assert "Polyline" not in geometry, (
            f"Simple format must not carry an encoded Polyline, got keys {list(geometry)!r}"
        )
        assert len(geometry["LineString"]) >= 2, (
            f"expected LineString with >=2 points, got {geometry['LineString']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
