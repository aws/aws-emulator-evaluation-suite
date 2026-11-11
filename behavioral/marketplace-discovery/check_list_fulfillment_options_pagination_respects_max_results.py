"""list-fulfillment-options-pagination-respects-max-results."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-fulfillment-options-pagination-respects-max-results"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListFulfillmentOptions one item at a time with maxResults=1 reassembles exactly
    the same set of fulfillment options, not just the same count, as a single unbounded call."""
    md = ctx.client("marketplace-discovery")
    product_id, full = _find_product_with_multiple_fulfillment_options(md)
    if product_id is None:
        raise AssertionError(
            "no scanned product (across up to 20 listing summaries) exposes 2+ fulfillment "
            "options; pagination cannot be meaningfully exercised"
        )

    paged = []
    token = None
    for _ in range(10):
        kwargs = {"productId": product_id, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = md.list_fulfillment_options(**kwargs)
        assert len(resp["fulfillmentOptions"]) <= 1, (
            f"maxResults=1 but got {len(resp['fulfillmentOptions'])} fulfillmentOptions in one page"
        )
        paged.extend(resp["fulfillmentOptions"])
        token = resp.get("nextToken")
        if not token:
            break

    assert len(paged) == len(full), (
        f"paginated collection returned {len(paged)} fulfillment options, "
        f"unbounded call returned {len(full)}"
    )
    full_json = sorted(json.dumps(o, sort_keys=True, default=str) for o in full)
    paged_json = sorted(json.dumps(o, sort_keys=True, default=str) for o in paged)
    assert paged_json == full_json, (
        "paginated fulfillment options are not the same set as the unbounded call's options"
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
            page = md.list_fulfillment_options(productId=product["productId"], maxResults=50)
            options = page["fulfillmentOptions"]
            if len(options) >= 2 and not page.get("nextToken"):
                return product["productId"], options
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
