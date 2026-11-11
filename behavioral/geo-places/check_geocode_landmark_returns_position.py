"""geocode-landmark-returns-position."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "geocode-landmark-returns-position"
GROUP = "geocoding"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode resolves a well-known landmark to its real-world coordinates."""
    geo = ctx.client("geo-places")
    resp = geo.geocode(QueryText="Space Needle, Seattle, WA, USA", MaxResults=1)
    items = resp.get("ResultItems", [])
    assert items, "expected at least one geocode result for a well-known landmark"
    item = items[0]
    assert item.get("PlaceId"), "geocode result must include a PlaceId"
    assert "space needle" in item["Title"].lower(), f"expected Space Needle, got title {item['Title']!r}"
    lng, lat = item["Position"]
    # Space Needle: 47.6205 N, 122.3493 W -- generous tolerance for provider variance.
    assert -122.40 <= lng <= -122.30, f"longitude {lng} not near Space Needle"
    assert 47.58 <= lat <= 47.66, f"latitude {lat} not near Space Needle"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
