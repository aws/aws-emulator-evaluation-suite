"""search-facets-returns-requested-facet-types-only."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-returns-requested-facet-types-only"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchFacets restricted to specific facetTypes returns only those types, well-formed."""
    md = ctx.client("marketplace-discovery")
    requested = ["CATEGORY", "PRICING_MODEL"]
    resp = md.search_facets(facetTypes=requested)

    assert resp["totalResults"] >= 1, f"expected at least one matching listing, got {resp['totalResults']}"
    listing_facets = resp["listingFacets"]
    assert listing_facets, "expected at least one facet type to be populated"
    extra_types = set(listing_facets.keys()) - set(requested)
    assert not extra_types, f"requested only {requested} but got extra facet types {sorted(extra_types)}"

    for facet_type, values in listing_facets.items():
        assert facet_type in requested, f"unrequested facet type {facet_type} leaked into the response"
        assert values, f"facet type {facet_type} was returned but had no values"
        for value in values:
            assert value["value"].strip(), f"facet {facet_type} has a blank value: {value!r}"
            assert value["displayName"].strip(), f"facet {facet_type} has a blank displayName: {value!r}"
            assert value["count"] >= 0, f"facet {facet_type} value {value['value']!r} has a negative count: {value['count']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
