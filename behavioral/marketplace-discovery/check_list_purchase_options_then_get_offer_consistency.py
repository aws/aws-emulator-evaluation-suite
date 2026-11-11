"""list-purchase-options-then-get-offer-consistency."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "list-purchase-options-then-get-offer-consistency"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_VALID_PRICING_MODEL_TYPES = {"USAGE", "CONTRACT", "BYOL", "FREE"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An OFFER purchase option discovered via ListPurchaseOptions resolves via GetOffer to the same identity."""
    md = ctx.client("marketplace-discovery")
    offer = _discover_offer(ctx)
    if offer is None:
        raise AssertionError(
            "no product in the sampled catalog had a purchase option with a resolvable offer "
            "visible to this caller"
        )

    resp = md.get_offer(offerId=offer["offer_id"])

    assert resp["offerId"] == offer["offer_id"], (
        f"GetOffer echoed offerId {resp['offerId']!r}, expected the requested {offer['offer_id']!r}"
    )
    assert resp["sellerOfRecord"]["sellerProfileId"] == offer["seller_profile_id"], (
        f"GetOffer sellerProfileId {resp['sellerOfRecord']['sellerProfileId']!r} does not match "
        f"the {offer['seller_profile_id']!r} ListPurchaseOptions reported for the same offer"
    )
    assert resp["sellerOfRecord"]["displayName"] == offer["seller_display_name"], (
        f"GetOffer seller displayName {resp['sellerOfRecord']['displayName']!r} does not match "
        f"the {offer['seller_display_name']!r} ListPurchaseOptions reported for the same offer"
    )
    assert resp["catalog"] == offer["catalog"], (
        f"GetOffer catalog {resp['catalog']!r} does not match the purchase option's own "
        f"catalog {offer['catalog']!r} for the same offer"
    )
    assert resp["pricingModel"]["pricingModelType"] in _VALID_PRICING_MODEL_TYPES, (
        f"GetOffer pricingModelType {resp['pricingModel']['pricingModelType']!r} is not one of "
        f"the documented values {_VALID_PRICING_MODEL_TYPES}"
    )


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
                    return {
                        "product_id": product_id,
                        "offer_id": offer_info["offerId"],
                        "seller_profile_id": offer_info["sellerOfRecord"]["sellerProfileId"],
                        "seller_display_name": offer_info["sellerOfRecord"]["displayName"],
                        "catalog": option["catalog"],
                        "purchase_option": option,
                    }
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
