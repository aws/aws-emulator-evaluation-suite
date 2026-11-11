"""search-listings-pricing-model-filter-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pricing-model-filter-matches"
GROUP = "search-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Filtering SearchListings by PRICING_MODEL only returns listings that carry that model."""
    client = ctx.client("marketplace-discovery")
    facets_resp = client.search_facets(facetTypes=["PRICING_MODEL"])
    pricing_facets = facets_resp["listingFacets"].get("PRICING_MODEL", [])
    facet = next((f for f in pricing_facets if f["count"] > 0), None)
    assert facet is not None, "expected at least one PRICING_MODEL facet with a non-zero count"
    pricing_value = facet["value"]

    search_resp = client.search_listings(
        filters=[{"filterType": "PRICING_MODEL", "filterValues": [pricing_value]}],
        maxResults=100,
    )
    assert search_resp["listingSummaries"], (
        f"expected at least one listing for PRICING_MODEL {pricing_value!r} "
        f"(facet reported count {facet['count']})"
    )
    for summary in search_resp["listingSummaries"]:
        model_types = {m["pricingModelType"] for m in summary["pricingModels"]}
        assert pricing_value in model_types, (
            f"listing {summary['listingId']} returned for PRICING_MODEL filter "
            f"{pricing_value!r} does not carry that pricing model: {model_types}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
