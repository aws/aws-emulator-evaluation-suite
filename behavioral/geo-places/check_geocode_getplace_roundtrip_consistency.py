"""geocode-getplace-roundtrip-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "geocode-getplace-roundtrip-consistency"
GROUP = "geocoding"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """For two distant landmarks, GetPlace on the PlaceId Geocode returns gives the same Title and a Position
    within 0.01 degrees, and the two landmarks resolve to different places.
    """
    geo = ctx.client("geo-places")

    def _roundtrip(query_text: str) -> tuple[str, str, float, float]:
        geocoded = geo.geocode(QueryText=query_text, MaxResults=1)
        items = geocoded.get("ResultItems", [])
        assert items, f"expected a geocode result for {query_text!r} to seed the round trip"
        first = items[0]
        place_id = first["PlaceId"]
        title = first["Title"]
        lng, lat = first["Position"]

        fetched = geo.get_place(PlaceId=place_id)
        assert fetched["Title"] == title, "GetPlace title must match the Geocode result it came from"
        f_lng, f_lat = fetched["Position"]
        assert abs(f_lng - lng) < 0.01, f"longitude drifted on roundtrip: {f_lng} vs {lng}"
        assert abs(f_lat - lat) < 0.01, f"latitude drifted on roundtrip: {f_lat} vs {lat}"
        return place_id, title, lng, lat

    needle_id, needle_title, needle_lng, needle_lat = _roundtrip("Space Needle, Seattle, WA, USA")
    bridge_id, bridge_title, bridge_lng, bridge_lat = _roundtrip(
        "Golden Gate Bridge, San Francisco, CA, USA"
    )

    assert needle_id != bridge_id, "two distinct landmarks resolved to the same PlaceId"
    assert needle_title != bridge_title, (
        f"two distinct landmarks resolved to the same title {needle_title!r} -- "
        "roundtrip may be echoing one canned place regardless of query"
    )
    assert abs(needle_lng - bridge_lng) > 1.0 or abs(needle_lat - bridge_lat) > 1.0, (
        "two landmarks ~1300km apart resolved to nearly identical coordinates"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
