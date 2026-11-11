"""list-purchase-options-invalid-filter-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-purchase-options-invalid-filter-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPurchaseOptions rejects an unrecognized filterType enum value, while a real filter type still succeeds."""
    md = ctx.client("marketplace-discovery")
    product_id = _first_product_id(md)
    if product_id is None:
        raise AssertionError(
            "no scanned listing summary exposed a product association within the scan window"
        )

    # The required PRODUCT_ID filter rides along so the only broken thing is the
    # unrecognized filterType itself — without it, ValidationException would be ambiguous
    # between "bad enum value" and "missing required filter".
    error = _error(
        lambda: md.list_purchase_options(
            filters=[
                {"filterType": "NOT_A_REAL_FILTER_TYPE", "filterValues": ["x"]},
                {"filterType": "PRODUCT_ID", "filterValues": [product_id]},
            ]
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for filterType=NOT_A_REAL_FILTER_TYPE, got {error.get('Code')!r}"
    )
    expected_message = (
        "1 validation error detected: Value 'NOT_A_REAL_FILTER_TYPE' at "
        "'filters.1.member.filterType' failed to satisfy constraint: Member must satisfy enum "
        "value set: [PURCHASE_OPTION_TYPE, VISIBILITY_SCOPE, PRODUCT_ID, AVAILABILITY_STATUS, "
        "SELLER_OF_RECORD_PROFILE_ID]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control in the same file: the identical PRODUCT_ID filter, without the bad
    # entry, succeeds and actually returns options associated with that product — not just
    # that the call returns without raising.
    resp = md.list_purchase_options(
        filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
        maxResults=25,
    )
    options = resp.get("purchaseOptions", [])
    if not options:
        raise AssertionError(
            f"no purchase options are visible to this caller account for product {product_id!r}"
        )
    for option in options:
        product_ids = {e["product"]["productId"] for e in option["associatedEntities"]}
        assert product_id in product_ids, (
            f"purchase option {option.get('purchaseOptionId')} returned by a "
            f"PRODUCT_ID={product_id} filter does not actually reference that product "
            f"(referenced: {product_ids})"
        )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
