"""search-facets-count-matches-filtered-search-total."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-count-matches-filtered-search-total"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CATEGORY facet's count exactly equals the totalResults of SearchListings filtered by that value."""
    md = ctx.client("marketplace-discovery")
    facets = md.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets["listingFacets"].get("CATEGORY", [])
    if not category_facets:
        raise AssertionError("no CATEGORY facet values were returned for the public catalog")
    # A zero-count facet makes the comparison a tautological 0 == 0, and a very high-count
    # facet risks the two APIs capping/estimating a broad query differently. The smallest
    # nonzero count keeps the filtered SearchListings call exact.
    candidates = [f for f in category_facets if f.get("count", 0) > 0]
    if not candidates:
        raise AssertionError("no CATEGORY facet value had a nonzero count")
    facet = min(candidates, key=lambda f: f["count"])

    filtered = md.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [facet["value"]]}],
        maxResults=1,
    )

    assert filtered["totalResults"] == facet["count"], (
        f"facet count {facet['count']} for category {facet['value']!r} does not match "
        f"SearchListings totalResults {filtered['totalResults']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
