"""get-offer-terms-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-terms-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _discover_offer_id(ctx) -> str | None:
    """Find any OFFER-type purchase option through public catalog products (ListPurchaseOptions
    filtered by PRODUCT_ID). GetOfferTerms's maxResults range does not depend on the offer's
    visibility scope, and a fresh account may have no private offers, so public offers are used
    as the positive control."""
    client = ctx.client("marketplace-discovery")
    search = client.search_listings(maxResults=25)
    product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids[:10]:
        po_resp = client.list_purchase_options(
            filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
            maxResults=25,
        )
        for option in po_resp.get("purchaseOptions", []):
            for entity in option["associatedEntities"]:
                if entity.get("offer"):
                    return entity["offer"]["offerId"]
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOfferTerms rejects maxResults=26 (the documented range is 1-25) with ValidationException."""
    client = ctx.client("marketplace-discovery")

    offer_id = _discover_offer_id(ctx)
    if offer_id is None:
        raise AssertionError(
            "no OFFER-type purchase option discoverable via search_listings + "
            "list_purchase_options(PRODUCT_ID=...) to use as a positive control"
        )

    control = client.get_offer_terms(offerId=offer_id, maxResults=25)
    assert isinstance(control.get("offerTerms"), list), (
        f"the in-range positive control (maxResults=25) did not return a list offerTerms: "
        f"{control!r}"
    )

    error = _error(lambda: client.get_offer_terms(offerId=offer_id, maxResults=26))
    assert error.get("Code") == "ValidationException", (
        f"maxResults=26 (above the documented 1-25 range) was rejected with {error.get('Code')!r}, "
        f'expected "ValidationException"'
    )
    expected_message = (
        "1 validation error detected: Value '26' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 25"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
