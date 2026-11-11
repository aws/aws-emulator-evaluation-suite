"""get-offer-terms-structural-union-single-field."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-offer-terms-structural-union-single-field"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_TERM_MEMBERS = {
    "byolPricingTerm",
    "configurableUpfrontPricingTerm",
    "fixedUpfrontPricingTerm",
    "freeTrialPricingTerm",
    "legalTerm",
    "paymentScheduleTerm",
    "recurringPaymentTerm",
    "renewalTerm",
    "supportTerm",
    "usageBasedPricingTerm",
    "validityTerm",
    "variablePaymentTerm",
    "netPaymentTerm",
}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOfferTerms returns a list of terms where each element carries exactly one recognized term type."""
    md = ctx.client("marketplace-discovery")
    offer = _discover_offer(ctx)
    if offer is None:
        raise AssertionError(
            "no product in the sampled catalog had a purchase option with a resolvable offer "
            "visible to this caller"
        )

    resp = md.get_offer_terms(offerId=offer["offer_id"], maxResults=25)

    terms = resp["offerTerms"]
    assert isinstance(terms, list), f"expected offerTerms to be a list, got {type(terms)!r}"
    assert terms, f"offer {offer['offer_id']!r} returned no terms to inspect"
    for term in terms:
        set_members = [key for key in term if term.get(key) is not None]
        assert len(set_members) == 1, f"expected exactly one term type set, got {set_members}"
        assert set_members[0] in _TERM_MEMBERS, f"unrecognized offer term type {set_members[0]}"


def _discover_offer(ctx) -> dict[str, Any] | None:
    md = ctx.client("marketplace-discovery")
    search = md.search_listings(maxResults=25)
    product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids[:10]:
        try:
            purchase = md.list_purchase_options(
                filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
                maxResults=10,
            )
        except Exception:
            continue
        for option in purchase.get("purchaseOptions", []):
            for assoc in option.get("associatedEntities", []):
                offer_info = assoc.get("offer")
                if offer_info:
                    return {"product_id": product_id, "offer_id": offer_info["offerId"]}
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
