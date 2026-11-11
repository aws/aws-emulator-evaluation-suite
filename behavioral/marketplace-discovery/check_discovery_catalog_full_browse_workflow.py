"""discovery-catalog-full-browse-workflow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "discovery-catalog-full-browse-workflow"
GROUP = "e2e_workflows"
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
    """SearchListings -> GetListing -> GetProduct/ListFulfillmentOptions -> GetOffer/GetOfferTerms
    resolve one consistent chain: each hop returns the ids the previous hop named, the offer references the
    listing's product, and every fulfillment option and offer term has exactly one union member set."""
    md = ctx.client("marketplace-discovery")
    found = _find_listing_with_offer(md)
    if found is None:
        raise AssertionError(
            "no scanned listing exposed both a product and an offer association within the scan "
            "window; a listing with a resolvable default offer is required to exercise this chain"
        )
    listing, offer_info, product_info = found
    listing_id = listing["listingId"]
    product_id = product_info["productId"]

    # Hop 1: GetListing detail (already fetched by the scan) must self-reference the same listingId
    # and must be reachable independently, confirming SearchListings -> GetListing consistency.
    relisted = md.get_listing(listingId=listing_id)
    assert relisted["listingId"] == listing_id
    assert relisted["listingName"] == listing["listingName"]

    # Hop 2: the product referenced by the listing resolves via GetProduct.
    product = md.get_product(productId=product_id)
    assert product["productId"] == product_id
    assert product["deployedOnAws"] in ("DEPLOYED", "NOT_DEPLOYED", "NOT_APPLICABLE")

    # Hop 3: that same product's fulfillment options resolve via ListFulfillmentOptions, and each
    # returned item is a well-formed union with exactly one member set (a real structural check,
    # not just presence).
    fulfillment = md.list_fulfillment_options(productId=product_id)
    for item in fulfillment["fulfillmentOptions"]:
        set_members = [k for k, v in item.items() if v is not None]
        assert len(set_members) == 1, (
            f"fulfillment option union item for product {product_id} has "
            f"{len(set_members)} members set, expected exactly 1: {item!r}"
        )

    # Hop 4: the offer referenced by the listing resolves via GetOffer, and cross-references the
    # same product this whole journey has been walking.
    offer = md.get_offer(offerId=offer_info["offerId"])
    assert offer["offerId"] == offer_info["offerId"]
    product_ids_in_offer = {e["product"]["productId"] for e in offer["associatedEntities"]}
    assert product_id in product_ids_in_offer

    # Hop 5: that offer's terms resolve via GetOfferTerms, completing the browse-to-terms journey.
    # The terminal read must be able to fail: terms must actually exist, and each must be a
    # well-formed OfferTerm union with exactly one variant populated -- not just a list-shaped
    # response.
    terms = md.get_offer_terms(offerId=offer_info["offerId"], maxResults=25)["offerTerms"]
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
