"""calculate-isolines-destination-based-snaps-destination-not-origin."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-destination-based-snaps-destination-not-origin"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

DESTINATION = [-122.3410, 47.6089]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines with only a Destination returns one isoline and a [lon, lat] SnappedDestination, and
    no SnappedOrigin.
    """
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Destination=DESTINATION, Thresholds={"Time": [600]}
    )

    isolines = resp["Isolines"]
    assert len(isolines) == 1, f"expected exactly 1 isoline, got {len(isolines)}: {isolines}"
    assert "SnappedDestination" in resp, f"expected SnappedDestination in response, got keys {sorted(resp)}"
    snapped = resp["SnappedDestination"]
    assert len(snapped) == 2, f"expected SnappedDestination to be a [lon, lat] pair, got {snapped}"
    assert "SnappedOrigin" not in resp, f"no Origin was supplied, so SnappedOrigin must be absent, got {resp.get('SnappedOrigin')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
