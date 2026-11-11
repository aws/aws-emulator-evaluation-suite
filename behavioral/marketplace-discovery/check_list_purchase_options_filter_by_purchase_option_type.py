"""list-purchase-options-filter-by-purchase-option-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-purchase-options-filter-by-purchase-option-type"
GROUP = "purchase-options"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering ListPurchaseOptions by PURCHASE_OPTION_TYPE=OFFER only returns OFFER entries."""
    client = ctx.client("marketplace-discovery")
    product_id, options = _first_offer_scoped_options(client)
    if options is None:
        raise AssertionError(
            "no product in the sampled catalog had a visible OFFER-type purchase option to "
            "verify the PURCHASE_OPTION_TYPE filter against"
        )
    for option in options:
        assert option["purchaseOptionType"] == "OFFER", (
            f"PURCHASE_OPTION_TYPE=OFFER filter for product {product_id!r} returned "
            f"purchase option {option.get('purchaseOptionId')!r} with type "
            f"{option.get('purchaseOptionType')!r}"
        )


def _first_offer_scoped_options(md, max_scan: int = 25, max_products: int = 10):
    """Scan the public catalog for a product whose OFFER-type purchase options are non-empty.

    ListPurchaseOptions requires at least a PRODUCT_ID or VISIBILITY_SCOPE filter in addition to
    any other filters; PRODUCT_ID (discovered from the public catalog, unlike VISIBILITY_SCOPE=
    PRIVATE) is guaranteed to be satisfiable by any caller, not just one with a negotiated private
    offer.
    """
    search = md.search_listings(maxResults=max_scan)
    product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for entity in summary["associatedEntities"]:
            product = entity.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids[:max_products]:
        resp = md.list_purchase_options(
            filters=[
                {"filterType": "PRODUCT_ID", "filterValues": [product_id]},
                {"filterType": "PURCHASE_OPTION_TYPE", "filterValues": ["OFFER"]},
            ],
            maxResults=100,
        )
        options = resp.get("purchaseOptions", [])
        if options:
            return product_id, options
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
