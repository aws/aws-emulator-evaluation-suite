"""suggest-returns-results-for-partial-query."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "suggest-returns-results-for-partial-query"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Suggest returns typed, relevant results (Place or Query) for a partial, ambiguous query."""
    geo = ctx.client("geo-places")
    resp = geo.suggest(
        QueryText="Starbucks Seattle",
        BiasPosition=[-122.3493, 47.6205],
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Suggest to return at least one result"

    titles = [i["Title"] for i in items]
    relevant = [i for i in items if "starbucks" in i["Title"].lower()]
    assert relevant, f"expected a Starbucks suggestion among results for 'Starbucks Seattle', got {titles}"

    for item in items:
        item_type = item["SuggestResultItemType"]
        assert item_type in ("Place", "Query"), (
            f"unexpected SuggestResultItemType: {item_type}"
        )
        assert item.get("Title"), "every suggestion must carry a display Title"
        if item_type == "Place":
            assert item.get("Place", {}).get("PlaceId"), (
                f"Place-typed suggestion missing a resolvable PlaceId: {item}"
            )
        else:
            assert item.get("Query", {}).get("QueryId"), (
                f"Query-typed suggestion missing a completable QueryId: {item}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
