"""search-facets-category-counts-consistent-with-search-listings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-category-counts-consistent-with-search-listings"
GROUP = "search-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CATEGORY facet count from SearchFacets matches SearchListings' totalResults for that filter."""
    client = ctx.client("marketplace-discovery")
    facets_resp = client.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets_resp["listingFacets"].get("CATEGORY", [])
    candidates = [f for f in category_facets if f["count"] > 0]
    assert candidates, "expected at least one CATEGORY facet with a non-zero count"
    # Pick the smallest nonzero count: a very popular category's totalResults may be capped/
    # estimated differently between the two APIs for broad queries, so keep the comparison exact.
    facet = min(candidates, key=lambda f: f["count"])
    category_value = facet["value"]

    search_resp = client.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [category_value]}],
        maxResults=100,
    )
    assert search_resp["totalResults"] == facet["count"], (
        "SearchListings totalResults for a CATEGORY filter must match the SearchFacets "
        f"count for the same category value ({search_resp['totalResults']} != {facet['count']})"
    )
    for summary in search_resp["listingSummaries"][:5]:
        cat_ids = {c["categoryId"] for c in summary["categories"]}
        assert category_value in cat_ids, (
            f"listing {summary['listingId']} returned for CATEGORY filter {category_value!r} "
            f"does not carry that category: {cat_ids}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
