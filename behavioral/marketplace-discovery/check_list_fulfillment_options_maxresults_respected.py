"""list-fulfillment-options-maxresults-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-fulfillment-options-maxresults-respected"
GROUP = "resource-lookup"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFulfillmentOptions never returns more options than the caller-supplied maxResults,
    and truncating a product known to have 2+ options still signals the remainder via
    nextToken."""
    client = ctx.client("marketplace-discovery")
    product_id, full = _find_product_with_multiple_fulfillment_options(client)
    if product_id is None:
        raise AssertionError(
            "no scanned product (across up to 20 listing summaries) exposes 2+ fulfillment "
            "options; maxResults truncation cannot be meaningfully exercised"
        )

    resp = client.list_fulfillment_options(productId=product_id, maxResults=1)
    options = resp["fulfillmentOptions"]
    assert len(options) == 1, (
        f"product {product_id} has {len(full)} fulfillment options but maxResults=1 "
        f"returned {len(options)}"
    )
    assert resp.get("nextToken"), (
        f"product {product_id} has {len(full)} fulfillment options but no nextToken was "
        "returned after a maxResults=1 page"
    )


def _find_product_with_multiple_fulfillment_options(md, max_scan: int = 20):
    resp = md.search_listings(maxResults=max_scan)
    seen_product_ids = set()
    for summary in resp["listingSummaries"]:
        for entity in summary["associatedEntities"]:
            product = entity.get("product")
            if not product or product["productId"] in seen_product_ids:
                continue
            seen_product_ids.add(product["productId"])
            options = md.list_fulfillment_options(
                productId=product["productId"], maxResults=50
            )["fulfillmentOptions"]
            if len(options) >= 2:
                return product["productId"], options
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
