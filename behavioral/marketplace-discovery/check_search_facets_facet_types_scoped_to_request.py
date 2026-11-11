"""search-facets-facet-types-scoped-to-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-facet-types-scoped-to-request"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When facetTypes explicitly requests only PUBLISHER, SearchFacets returns facet data scoped
    to that single type, not every available facet type."""
    md = ctx.client("marketplace-discovery")
    resp = md.search_facets(facetTypes=["PUBLISHER"])
    assert resp["totalResults"] >= 1, (
        f"expected the public marketplace catalog to have publisher-facetable listings, "
        f"got totalResults={resp['totalResults']}"
    )
    returned_types = set(resp["listingFacets"].keys())
    assert returned_types == {"PUBLISHER"}, (
        f"expected listingFacets keys == {{'PUBLISHER'}}, got {returned_types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
