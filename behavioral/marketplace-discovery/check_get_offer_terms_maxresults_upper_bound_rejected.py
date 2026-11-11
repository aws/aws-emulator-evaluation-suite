"""get-offer-terms-maxresults-upper-bound-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-terms-maxresults-upper-bound-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOfferTerms rejects maxResults above the documented max of 25; 25 itself still succeeds."""
    client = ctx.client("marketplace-discovery")
    offer_id = _discover_offer_id(ctx)
    if offer_id is None:
        raise AssertionError(
            "no product in the sampled catalog had a purchase option with a resolvable "
            "offer visible to this caller"
        )

    error = _client_error(lambda: client.get_offer_terms(offerId=offer_id, maxResults=26))
    assert error.get("Code") == "ValidationException", (
        f"maxResults=26 (above the documented ceiling of 25) was rejected with "
        f"{error.get('Code')!r}, expected 'ValidationException'"
    )
    expected_message = (
        "1 validation error detected: Value '26' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 25"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: the documented upper bound itself is accepted.
    resp = client.get_offer_terms(offerId=offer_id, maxResults=25)
    assert isinstance(resp["offerTerms"], list), (
        f"maxResults=25 (the documented ceiling) was rejected or returned a non-list "
        f"offerTerms: {resp.get('offerTerms')!r}"
    )
    for term in resp["offerTerms"]:
        assert isinstance(term, dict) and term, f"each offer term must be a non-empty structure, got {term!r}"


def _discover_offer_id(ctx, max_products: int = 10):
    client = ctx.client("marketplace-discovery")
    search = client.search_listings(maxResults=25)
    product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids[:max_products]:
        try:
            purchase = client.list_purchase_options(
                filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
                maxResults=10,
            )
        except Exception:
            continue
        for option in purchase.get("purchaseOptions", []):
            for assoc in option.get("associatedEntities", []):
                offer_info = assoc.get("offer")
                if offer_info:
                    return offer_info["offerId"]
    return None


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects maxResults=26, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
