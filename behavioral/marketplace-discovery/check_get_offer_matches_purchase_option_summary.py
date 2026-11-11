"""get-offer-matches-purchase-option-summary."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-matches-purchase-option-summary"
GROUP = "consistency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOffer on an offerId referenced by an OFFER-type purchase option matches that reference."""
    client = ctx.client("marketplace-discovery")
    offer_info = _discover_offer_info(client)
    if offer_info is None:
        raise AssertionError(
            "no product in the sampled catalog had an OFFER-type purchase option with a "
            "resolvable offer association visible to this caller"
        )

    offer = client.get_offer(offerId=offer_info["offerId"])

    assert offer["offerId"] == offer_info["offerId"], (
        f"GetOffer returned offerId {offer['offerId']!r}, expected {offer_info['offerId']!r} "
        "from the ListPurchaseOptions summary"
    )
    assert offer["sellerOfRecord"]["sellerProfileId"] == offer_info["sellerOfRecord"]["sellerProfileId"], (
        f"GetOffer sellerProfileId {offer['sellerOfRecord']['sellerProfileId']!r} does not match "
        f"the ListPurchaseOptions summary reference {offer_info['sellerOfRecord']['sellerProfileId']!r}"
    )
    if offer_info.get("offerName"):
        assert offer.get("offerName") == offer_info["offerName"], (
            f"GetOffer offerName {offer.get('offerName')!r} does not match the ListPurchaseOptions "
            f"summary reference {offer_info['offerName']!r}"
        )


def _discover_offer_info(client, max_products: int = 25) -> dict | None:
    """Find an OFFER-type purchase option's offer reference via a public catalog product.

    ListPurchaseOptions requires PRODUCT_ID or VISIBILITY_SCOPE=PRIVATE as a base filter; PRIVATE
    only surfaces offers privately extended to this caller, which a fresh account never has. Seeding
    from SearchListings' public products and filtering by PRODUCT_ID finds real OFFER associations
    without depending on a private-offer prerequisite this check has no way to create.
    """
    search = client.search_listings(maxResults=max_products)
    product_ids: list[str] = []
    for summary in search.get("listingSummaries", []):
        for assoc in summary.get("associatedEntities", []):
            product = assoc.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids:
        purchase = client.list_purchase_options(
            filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
            maxResults=25,
        )
        for option in purchase.get("purchaseOptions", []):
            if option.get("purchaseOptionType") != "OFFER":
                continue
            for entity in option.get("associatedEntities", []):
                offer_info = entity.get("offer")
                if offer_info:
                    return offer_info
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
