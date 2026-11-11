"""get-offer-badges-reflect-purchase-option-badges."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-offer-badges-reflect-purchase-option-badges"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The badges on an offer via GetOffer match the badges reported for it in ListPurchaseOptions."""
    offer = _discover_offer(ctx)
    if offer is None:
        raise AssertionError(
            "no product in the sampled catalog had a purchase option with a resolvable offer "
            "visible to this caller"
        )

    md = ctx.client("marketplace-discovery")
    resp = md.get_offer(offerId=offer["offer_id"])

    offer_badge_types = {b["badgeType"] for b in resp["badges"]}
    purchase_option_badge_types = {b["badgeType"] for b in offer["purchase_option"].get("badges", [])}

    assert offer_badge_types == purchase_option_badge_types, (
        f"GetOffer badges {offer_badge_types} do not match ListPurchaseOptions badges "
        f"{purchase_option_badge_types} for the same offer {offer['offer_id']}"
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
            for assoc in option["associatedEntities"]:
                offer_info = assoc.get("offer")
                if offer_info:
                    return {
                        "product_id": product_id,
                        "offer_id": offer_info["offerId"],
                        "purchase_option": option,
                    }
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
