"""get-offer-via-purchase-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-via-purchase-options"
GROUP = "resource-lookup"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An OFFER-type purchase option discovered via ListPurchaseOptions resolves via GetOffer."""
    client = ctx.client("marketplace-discovery")
    offer = _discover_offer_info(client)
    if offer is None:
        raise AssertionError(
            "no product in the sampled catalog had an OFFER-type purchase option with a "
            "resolvable offer association visible to this caller"
        )
    detail = client.get_offer(offerId=offer["offerId"])
    assert detail["offerId"] == offer["offerId"], (
        f"GetOffer offerId {detail['offerId']!r} does not match the ListPurchaseOptions "
        f"offer reference {offer['offerId']!r} it was resolved from"
    )
    assert detail["sellerOfRecord"]["sellerProfileId"] == offer["sellerOfRecord"]["sellerProfileId"], (
        f"GetOffer sellerProfileId {detail['sellerOfRecord']['sellerProfileId']!r} does not match "
        f"the purchase option's {offer['sellerOfRecord']['sellerProfileId']!r}"
    )
    assert detail["pricingModel"]["pricingModelType"], (
        "GetOffer must report a non-empty pricingModelType"
    )
    assert detail["agreementProposalId"], "GetOffer must report a non-empty agreementProposalId"
    assert detail["associatedEntities"], "GetOffer must always report an associated product"
    assert detail["associatedEntities"][0]["product"]["productId"], (
        "GetOffer's first associated entity must carry a non-empty product productId"
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
