"""search-nearby-results-within-radius."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-nearby-results-within-radius"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchNearby only returns places whose reported Distance is within QueryRadius,
    and shrinking QueryRadius genuinely drops farther results rather than just
    happening to satisfy a distance check against a fixed-size page.
    """
    geo = ctx.client("geo-places")
    position = [-122.3493, 47.6205]  # Space Needle, downtown Seattle
    narrow_radius, wide_radius = 40, 85

    narrow = geo.search_nearby(QueryPosition=position, QueryRadius=narrow_radius, MaxResults=20)
    wide = geo.search_nearby(QueryPosition=position, QueryRadius=wide_radius, MaxResults=20)
    narrow_items = narrow.get("ResultItems", [])
    wide_items = wide.get("ResultItems", [])

    assert narrow_items, "expected SearchNearby to find POIs near downtown Seattle"
    for item in narrow_items:
        assert item["Distance"] <= narrow_radius, (
            f"result {item.get('Title')} reported distance {item['Distance']}m "
            f"exceeds query radius {narrow_radius}m"
        )
    for item in wide_items:
        assert item["Distance"] <= wide_radius, (
            f"result {item.get('Title')} reported distance {item['Distance']}m "
            f"exceeds query radius {wide_radius}m"
        )

    # Both radii are small enough that MaxResults=20 does not saturate near this point
    # (a 500m radius already fills 20 results within ~90m), so a strict
    # increase in count when the radius widens is evidence QueryRadius is a real
    # filter and not incidental: a target that ignored QueryRadius and just returned
    # its nearest page would report the same count and the same places at both radii.
    assert len(wide_items) > len(narrow_items), (
        f"widening QueryRadius from {narrow_radius}m to {wide_radius}m did not surface any "
        f"additional results ({len(narrow_items)} places at both radii) -- QueryRadius may "
        f"not be enforced as a real filter"
    )
    narrow_ids = {item["PlaceId"] for item in narrow_items}
    wide_ids = {item["PlaceId"] for item in wide_items}
    assert narrow_ids <= wide_ids, (
        f"the narrower radius's results were not a subset of the wider radius's results: "
        f"{narrow_ids - wide_ids} appeared at {narrow_radius}m but vanished at {wide_radius}m"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
