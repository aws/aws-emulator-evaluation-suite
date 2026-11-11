"""search-listings-totalresults-stable-across-sort-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-totalresults-stable-across-sort-order"
GROUP = "search-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Changing sortBy/sortOrder must not change SearchListings' totalResults for the same filters."""
    client = ctx.client("marketplace-discovery")
    facets_resp = client.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets_resp["listingFacets"].get("CATEGORY", [])
    candidates = [f for f in category_facets if f["count"] > 0]
    assert candidates, "expected at least one CATEGORY facet with a non-zero count"
    # Pick the smallest nonzero count: a very popular category's totalResults may be capped/
    # estimated differently between the two APIs for broad queries, so keep the comparison exact.
    facet = min(candidates, key=lambda f: f["count"])
    filters = [{"filterType": "CATEGORY", "filterValues": [facet["value"]]}]

    descending = client.search_listings(
        filters=filters, sortBy="AVERAGE_CUSTOMER_RATING", sortOrder="DESCENDING", maxResults=10
    )
    ascending = client.search_listings(
        filters=filters, sortBy="AVERAGE_CUSTOMER_RATING", sortOrder="ASCENDING", maxResults=10
    )
    assert descending["totalResults"] == ascending["totalResults"], (
        "reversing sortOrder must not change the total matching-listing count "
        f"({descending['totalResults']} != {ascending['totalResults']})"
    )
    assert descending["totalResults"] == facet["count"], (
        f"SearchListings totalResults for CATEGORY filter {facet['value']!r} must match "
        f"the SearchFacets count for that category ({descending['totalResults']} != {facet['count']})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
