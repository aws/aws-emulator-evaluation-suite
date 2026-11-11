"""search-listings-category-filter-narrows-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-category-filter-narrows-results"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Filtering SearchListings by a CATEGORY facet value discovered via SearchFacets narrows (or
    matches) the unfiltered total, and every returned listing actually carries that category."""
    md = ctx.client("marketplace-discovery")
    facets = md.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets["listingFacets"].get("CATEGORY", [])
    candidate = next((f for f in category_facets if f["count"] > 0), None)
    if candidate is None:
        raise AssertionError("catalog exposed no CATEGORY facet values with a positive count")

    unfiltered_total = md.search_listings(maxResults=1)["totalResults"]
    filtered = md.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [candidate["value"]]}],
        maxResults=25,
    )
    assert filtered["totalResults"] <= unfiltered_total, (
        f"CATEGORY filter on {candidate['value']!r} returned totalResults="
        f"{filtered['totalResults']} which exceeds the unfiltered total={unfiltered_total}"
    )
    assert filtered["totalResults"] >= 1, (
        f"CATEGORY filter on {candidate['value']!r} (facet count={candidate['count']}) "
        "returned zero totalResults"
    )
    assert filtered["listingSummaries"], "expected at least one listing summary in the filtered page"
    for summary in filtered["listingSummaries"]:
        category_ids = {c["categoryId"] for c in summary["categories"]}
        assert candidate["value"] in category_ids, (candidate["value"], category_ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
