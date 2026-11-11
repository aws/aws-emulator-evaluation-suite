"""list-purchase-options-filter-by-product-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-purchase-options-filter-by-product-id"
GROUP = "purchase-options"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering ListPurchaseOptions by PRODUCT_ID alone returns a superset of the
    PRODUCT_ID+PURCHASE_OPTION_TYPE=OFFER result for the same product, and every returned option
    actually references that product."""
    client = ctx.client("marketplace-discovery")
    product_id, offer_options = _first_offer_scoped_options(client)
    if product_id is None:
        raise AssertionError(
            "no product in the sampled public catalog had a visible OFFER-type purchase option "
            "to seed the PRODUCT_ID filter from"
        )
    offer_ids = {o["purchaseOptionId"] for o in offer_options}

    filtered = client.list_purchase_options(
        filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
        maxResults=100,
    )
    filtered_options = filtered.get("purchaseOptions", [])
    assert filtered_options, f"expected at least one purchase option for product {product_id}"

    filtered_ids = {o["purchaseOptionId"] for o in filtered_options}
    assert offer_ids <= filtered_ids, (
        f"PRODUCT_ID={product_id} alone returned {filtered_ids}, missing the OFFER-typed "
        f"option(s) {offer_ids - filtered_ids} that the PRODUCT_ID+PURCHASE_OPTION_TYPE=OFFER "
        f"filter surfaced for the same product"
    )

    for option in filtered_options:
        product_ids = {e["product"]["productId"] for e in option["associatedEntities"]}
        assert product_id in product_ids, (
            f"purchase option {option['purchaseOptionId']} returned by a PRODUCT_ID={product_id} "
            f"filter does not actually reference that product (referenced: {product_ids})"
        )


def _first_offer_scoped_options(md, max_scan: int = 25, max_products: int = 10):
    """Scan the public catalog for a product with a visible OFFER-type purchase option.

    ListPurchaseOptions requires a PRODUCT_ID or VISIBILITY_SCOPE filter; PRODUCT_ID (discovered
    from the public catalog) is satisfiable by any caller, unlike VISIBILITY_SCOPE=PRIVATE, which
    only resolves for an account with a seller-negotiated private offer.
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
