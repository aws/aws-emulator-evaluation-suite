"""get-offer-terms-each-term-has-single-variant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-terms-each-term-has-single-variant"
GROUP = "cross-reference"
SERVICES = ["marketplace-discovery"]

_TERM_KEYS = [
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
]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOfferTerms returns a list of OfferTerm unions; each element has exactly one term
    variant populated, never zero or more than one."""
    md = ctx.client("marketplace-discovery")
    found = _find_listing_with_offer(md)
    if found is None:
        raise AssertionError(
            "no scanned listing exposed a resolvable default offer within the scan window"
        )
    _listing, offer_info, _product_info = found

    resp = md.get_offer_terms(offerId=offer_info["offerId"], maxResults=25)
    terms = resp["offerTerms"]
    if not terms:
        raise AssertionError(f"offer {offer_info['offerId']!r} has no terms to inspect")
    for term in terms:
        set_keys = [k for k in _TERM_KEYS if term.get(k) is not None]
        assert len(set_keys) == 1, f"expected exactly one populated term variant, got {set_keys}"


def _find_listing_with_offer(md, max_scan: int = 20):
    resp = md.search_listings(maxResults=max_scan)
    for summary in resp["listingSummaries"]:
        detail = md.get_listing(listingId=summary["listingId"])
        for entity in detail["associatedEntities"]:
            offer = entity.get("offer")
            product = entity.get("product")
            if offer and product:
                return detail, offer, product
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
