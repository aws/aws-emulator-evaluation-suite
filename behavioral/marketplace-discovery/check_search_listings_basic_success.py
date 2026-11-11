"""search-listings-basic-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-basic-success"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_PRICING_MODEL_TYPES = {"USAGE", "CONTRACT", "BYOL", "FREE"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings returns well-formed, fully-populated listing summaries."""
    md = ctx.client("marketplace-discovery")
    resp = md.search_listings(maxResults=10)

    assert resp["totalResults"] >= 1, "expected the public catalog to have at least one listing"
    summaries = resp["listingSummaries"]
    assert 1 <= len(summaries) <= 10

    for summary in summaries:
        assert summary["listingId"]
        assert summary["listingName"].strip()
        assert summary["catalog"]
        assert summary["shortDescription"].strip()
        assert summary["logoThumbnailUrl"]
        publisher = summary["publisher"]
        assert publisher["sellerProfileId"]
        assert publisher["displayName"]
        assert isinstance(summary["fulfillmentOptionSummaries"], list)
        assert isinstance(summary["categories"], list)
        assert isinstance(summary["badges"], list)
        assert isinstance(summary["associatedEntities"], list)
        # The model marks reviewSummary @required, but real AWS omits it for a listing
        # with no reviews rather than sending an empty reviewSourceSummaries list.
        review_summary = summary.get("reviewSummary")
        if review_summary is not None:
            assert isinstance(review_summary["reviewSourceSummaries"], list)
        pricing_models = summary["pricingModels"]
        assert isinstance(pricing_models, list)
        for pm in pricing_models:
            assert pm["pricingModelType"] in _PRICING_MODEL_TYPES
            assert pm["displayName"]
        pricing_units = summary.get("pricingUnits")
        if pricing_units is not None:
            assert isinstance(pricing_units, list)
            for pu in pricing_units:
                assert pu["pricingUnitType"]
                assert pu["displayName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
