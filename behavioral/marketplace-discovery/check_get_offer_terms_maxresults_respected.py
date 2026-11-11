"""get-offer-terms-maxresults-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-offer-terms-maxresults-respected"
GROUP = "resource-lookup"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOfferTerms never returns more terms than the caller-supplied maxResults, and the cap
    is proven against an offer independently confirmed to have more than one term available."""
    client = ctx.client("marketplace-discovery")
    offer_id = _discover_offer_with_multiple_terms(client)
    if offer_id is None:
        raise AssertionError(
            "no scanned listing's offer (across up to 20 listing summaries) exposes 2+ terms; "
            "maxResults truncation cannot be meaningfully exercised"
        )

    resp = client.get_offer_terms(offerId=offer_id, maxResults=1)
    assert len(resp["offerTerms"]) == 1, (
        f"expected exactly 1 term with maxResults=1 against an offer with >=2 terms, "
        f"got {len(resp['offerTerms'])}"
    )
    assert resp.get("nextToken"), (
        "maxResults=1 truncated a multi-term offer but returned no nextToken to fetch the rest"
    )


def _discover_offer_with_multiple_terms(client, max_scan: int = 20):
    resp = client.search_listings(maxResults=max_scan)
    seen_offer_ids = set()
    for summary in resp["listingSummaries"]:
        detail = client.get_listing(listingId=summary["listingId"])
        for entity in detail["associatedEntities"]:
            offer = entity.get("offer")
            if not offer or offer["offerId"] in seen_offer_ids:
                continue
            seen_offer_ids.add(offer["offerId"])
            terms = client.get_offer_terms(offerId=offer["offerId"], maxResults=25)["offerTerms"]
            if len(terms) >= 2:
                return offer["offerId"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
