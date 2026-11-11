"""e2e-suggest-searchtext-getplace-workflow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-suggest-searchtext-getplace-workflow"
GROUP = "e2e"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Suggest for 'Starbuck' yields a PlaceId directly or through SearchText on its QueryId, and GetPlace on
    that PlaceId returns a Starbucks Title, a Position and categories with an Id and a Name.
    """
    geo = ctx.client("geo-places")
    resp = geo.suggest(
        QueryText="Starbuck",
        BiasPosition=[-122.3493, 47.6205],  # downtown Seattle
        AdditionalFeatures=["Core"],
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Suggest to return at least one result for 'Starbuck'"

    query_items = [
        i for i in items
        if i.get("SuggestResultItemType") == "Query" and i.get("Query", {}).get("QueryId")
    ]
    place_items = [
        i for i in items
        if i.get("SuggestResultItemType") == "Place" and i.get("Place", {}).get("PlaceId")
    ]
    assert query_items or place_items, (
        f"expected at least one completable Suggest result, got types "
        f"{[i.get('SuggestResultItemType') for i in items]}"
    )

    if query_items:
        # Follow-up hop: complete the suggested query via SearchText's QueryId.
        query_id = query_items[0]["Query"]["QueryId"]
        completed = geo.search_text(QueryId=query_id)

        completed_items = completed.get("ResultItems", [])
        assert completed_items, "expected SearchText to resolve the Suggest QueryId to place results"
        place_id = completed_items[0]["PlaceId"]
    else:
        # Suggest already resolved directly to a place.
        place_id = place_items[0]["Place"]["PlaceId"]

    # Final hop: fetch full place details for whatever PlaceId the chain produced.
    fetched = geo.get_place(PlaceId=place_id)
    assert fetched.get("Title"), "expected GetPlace to resolve a Title for the workflow's PlaceId"
    assert "starbuck" in fetched["Title"].lower(), (
        f"expected the end-to-end workflow to resolve to a Starbucks place, got {fetched['Title']!r}"
    )
    assert fetched.get("Position"), "expected GetPlace to include a Position"
    categories = fetched.get("Categories", [])
    assert categories, f"expected non-empty Categories for a known POI, got {categories}"
    for category in categories:
        assert category.get("Id"), f"category missing Id: {category}"
        assert category.get("Name"), f"category missing Name: {category}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
