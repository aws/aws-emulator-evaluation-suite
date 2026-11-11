"""search-nearby-pagination-distinct-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-nearby-pagination-distinct-pages"
GROUP = "pagination"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchNearby's MaxResults truncates the page to the requested size with the same
    top-ranked place a wider page reports, and a returned NextToken advances to a disjoint
    result."""
    geo = ctx.client("geo-places")
    position = [-122.3493, 47.6205]  # Space Needle, downtown Seattle
    radius_m = 2000

    # Positive control: prove the vicinity holds multiple distinct places, so a
    # single-item MaxResults=1 page is a truncation effect, not the entire dataset.
    wide = geo.search_nearby(QueryPosition=position, QueryRadius=radius_m, MaxResults=5)
    wide_items = wide.get("ResultItems", [])
    wide_ids = [item["PlaceId"] for item in wide_items]
    assert len(wide_ids) >= 2, f"expected multiple POIs near the Space Needle within {radius_m}m, got {len(wide_ids)}"
    assert len(set(wide_ids)) == len(wide_ids), f"expected distinct PlaceIds in a single page, got {wide_ids}"

    first = geo.search_nearby(QueryPosition=position, QueryRadius=radius_m, MaxResults=1)
    first_items = first.get("ResultItems", [])
    assert len(first_items) == 1, f"expected MaxResults=1 to truncate to 1 item, got {len(first_items)}"
    first_place_id = first_items[0]["PlaceId"]
    assert first_place_id, "expected the truncated result to carry a PlaceId"
    assert "Position" in first_items[0], "expected the truncated result to carry a Position"
    assert first_place_id == wide_ids[0], (
        f"expected MaxResults=1's sole item ({first_place_id}) to be the same top-ranked "
        f"place a wider MaxResults=5 page reports ({wide_ids[0]}), not an arbitrary member "
        f"of the vicinity"
    )

    next_token = first.get("NextToken")
    if next_token:
        second = geo.search_nearby(
            QueryPosition=position,
            QueryRadius=radius_m,
            MaxResults=1,
            NextToken=next_token,
        )
        second_items = second.get("ResultItems", [])
        assert second_items, "expected a second page of results when NextToken was returned"
        second_place_id = second_items[0]["PlaceId"]
        assert second_place_id != first_place_id, (
            f"second page repeated the first page's PlaceId: {second_place_id}"
        )
    # else: SearchNearby may return no NextToken even when a wider page reports more
    # results (the `wide` positive control above); the rank-consistency assertion
    # above carries this check when that branch does not fire.







if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
