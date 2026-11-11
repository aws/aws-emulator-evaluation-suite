"""search-facets-category-present-with-counts."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-category-present-with-counts"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchFacets scoped to CATEGORY returns only CATEGORY facets, each with a positive count."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_facets(facetTypes=["CATEGORY"])
    facets = resp.get("listingFacets", {})

    if not facets.get("CATEGORY"):
        raise AssertionError("no CATEGORY facets visible to this account in the catalog")

    # requesting only CATEGORY must not surface other facet types
    assert set(facets.keys()) == {"CATEGORY"}, f"unexpected facet types returned: {sorted(facets.keys())}"

    category_facets = facets["CATEGORY"]
    assert len(category_facets) > 0, "CATEGORY key present but its facet list is empty"
    for facet in category_facets:
        assert facet["value"], f"CATEGORY facet missing a non-empty value: {facet!r}"
        assert facet["displayName"], f"CATEGORY facet missing a non-empty displayName: {facet!r}"
        assert facet["count"] >= 1, f"CATEGORY facet {facet['value']!r} reported count {facet['count']}, expected >= 1"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
