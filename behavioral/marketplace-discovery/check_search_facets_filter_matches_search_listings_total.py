"""search-facets-filter-matches-search-listings-total."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-filter-matches-search-listings-total"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CATEGORY facet's reported count matches SearchListings' totalResults when filtered by that same category."""
    client = ctx.client("marketplace-discovery")
    facet_resp = client.search_facets(facetTypes=["CATEGORY"])
    facets = facet_resp.get("listingFacets", {}).get("CATEGORY", [])
    if not facets:
        raise AssertionError("no CATEGORY facets visible to this account")

    candidates = [f for f in facets if f["count"] > 0]
    if not candidates:
        raise AssertionError("no CATEGORY facet reported a nonzero count")
    # A very popular category's totalResults may be capped/estimated differently between the two
    # APIs for broad queries, so the smallest nonzero count keeps the comparison exact.
    facet = min(candidates, key=lambda f: f["count"])

    search_resp = client.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [facet["value"]]}],
        maxResults=1,
    )

    assert search_resp["totalResults"] == facet["count"], (
        f"facet count {facet['count']} for category {facet['value']!r} did not match "
        f"SearchListings totalResults {search_resp['totalResults']} for the identical filter"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
