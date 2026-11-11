"""search-facets-total-results-matches-search-listings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-total-results-matches-search-listings"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The listing count SearchFacets reports for one PUBLISHER facet value equals the totalResults
    SearchListings reports when filtered to that value, so facet counts reflect the live catalog."""
    md = ctx.client("marketplace-discovery")
    facets_resp = md.search_facets(facetTypes=["PUBLISHER"])
    publisher_facets = facets_resp["listingFacets"].get("PUBLISHER", [])
    assert publisher_facets, "expected at least one PUBLISHER facet value in the catalog"

    # Pick a facet value with a small, nonzero count so the filtered SearchListings call stays
    # well under any result-count cap the service may apply to large unfiltered/broad queries.
    candidates = [f for f in publisher_facets if f.get("count", 0) > 0]
    assert candidates, "expected at least one PUBLISHER facet value with a positive count"
    candidate = min(candidates, key=lambda f: f["count"])
    filter_value = candidate["value"]
    expected_count = candidate["count"]

    listings_total = md.search_listings(
        filters=[{"filterType": "PUBLISHER", "filterValues": [filter_value]}],
        maxResults=1,
    )["totalResults"]
    assert listings_total == expected_count, (listings_total, expected_count, filter_value)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
