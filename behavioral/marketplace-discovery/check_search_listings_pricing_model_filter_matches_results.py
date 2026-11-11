"""search-listings-pricing-model-filter-matches-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pricing-model-filter-matches-results"
GROUP = "facets"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering SearchListings by a PRICING_MODEL facet value discovered via SearchFacets returns
    only listings that actually advertise that pricing model."""
    md = ctx.client("marketplace-discovery")
    facets = md.search_facets(facetTypes=["PRICING_MODEL"])
    pm_facets = facets["listingFacets"].get("PRICING_MODEL", [])
    candidate = next((f for f in pm_facets if f["count"] > 0), None)
    if candidate is None:
        raise AssertionError("catalog exposed no PRICING_MODEL facet values with a positive count")

    filtered = md.search_listings(
        filters=[{"filterType": "PRICING_MODEL", "filterValues": [candidate["value"]]}],
        maxResults=25,
    )
    assert filtered["totalResults"] == candidate["count"], (
        f"facet count {candidate['count']} for PRICING_MODEL {candidate['value']!r} does not "
        f"match SearchListings totalResults {filtered['totalResults']} for the identical filter"
    )
    assert filtered["listingSummaries"], "expected at least one listing summary in the filtered page"
    for summary in filtered["listingSummaries"]:
        pricing_model_types = {pm["pricingModelType"] for pm in summary["pricingModels"]}
        assert candidate["value"] in pricing_model_types, (candidate["value"], pricing_model_types)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
