"""search-listings-category-filter-monotonic-reduction."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-category-filter-monotonic-reduction"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Filtering SearchListings by a real category never returns more results than the unfiltered search."""
    md = ctx.client("marketplace-discovery")
    unfiltered = md.search_listings(maxResults=1)
    total_unfiltered = unfiltered["totalResults"]

    facets = md.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets["listingFacets"].get("CATEGORY", [])
    if not category_facets:
        raise AssertionError("no CATEGORY facet values were returned for the public catalog")
    facet = category_facets[0]
    category_value = facet["value"]
    facet_count = facet["count"]
    assert facet_count >= 1

    filtered = md.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [category_value]}],
        maxResults=10,
    )
    total_filtered = filtered["totalResults"]

    assert total_filtered >= 1
    assert total_filtered <= total_unfiltered, (
        "a category-filtered search must not return more results than the unfiltered search"
    )
    summaries = filtered["listingSummaries"]
    assert summaries, "expected at least one listing summary in the filtered page"
    for summary in summaries:
        category_ids = {c["categoryId"] for c in summary["categories"]}
        assert category_value in category_ids, (
            f"listing {summary['listingId']} returned under CATEGORY filter {category_value!r} "
            f"does not carry that category: {category_ids}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
