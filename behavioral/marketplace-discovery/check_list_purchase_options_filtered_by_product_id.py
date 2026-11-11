"""list-purchase-options-filtered-by-product-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-purchase-options-filtered-by-product-id"
GROUP = "purchase-options"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPurchaseOptions filtered by PRODUCT_ID only returns purchase options that are actually
    associated with that product."""
    md = ctx.client("marketplace-discovery")
    product_id = _first_product_id(md)
    if product_id is None:
        raise AssertionError(
            "no scanned listing summary exposed a product association within the scan window"
        )

    resp = md.list_purchase_options(
        filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
        maxResults=25,
    )
    options = resp.get("purchaseOptions", [])
    if not options:
        raise AssertionError(
            f"no purchase options are visible to this caller account for product {product_id!r}"
        )
    for opt in options:
        product_ids = {e["product"]["productId"] for e in opt["associatedEntities"]}
        assert product_id in product_ids, (product_id, product_ids)


def _first_product_id(md, max_scan: int = 20):
    resp = md.search_listings(maxResults=max_scan)
    for summary in resp["listingSummaries"]:
        for entity in summary["associatedEntities"]:
            product = entity.get("product")
            if product:
                return product["productId"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
