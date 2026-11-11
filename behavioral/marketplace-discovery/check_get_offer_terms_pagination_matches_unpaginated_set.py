"""get-offer-terms-pagination-matches-unpaginated-set."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-offer-terms-pagination-matches-unpaginated-set"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating GetOfferTerms one term at a time reassembles exactly the same set as a single unpaginated call."""
    client = ctx.client("marketplace-discovery")
    offer_id, baseline_terms = _discover_bounded_offer(client)
    if offer_id is None:
        raise AssertionError(
            "no scanned listing's associated offer (within 20 listings) has 2-25 terms; "
            "pagination cannot be meaningfully cross-checked against an unpaginated call"
        )

    paged_terms = []
    token = None
    for _ in range(len(baseline_terms) + 2):
        kwargs = {"offerId": offer_id, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = client.get_offer_terms(**kwargs)
        paged_terms.extend(page["offerTerms"])
        token = page.get("nextToken")
        if not token:
            break

    assert len(paged_terms) == len(baseline_terms), (
        f"paginated collection returned {len(paged_terms)} terms, unpaginated call returned {len(baseline_terms)}"
    )
    baseline_json = sorted(json.dumps(t, sort_keys=True, default=str) for t in baseline_terms)
    paged_json = sorted(json.dumps(t, sort_keys=True, default=str) for t in paged_terms)
    assert paged_json == baseline_json, "paginated terms are not the same set as the unpaginated terms"


def _discover_bounded_offer(client, max_scan: int = 20):
    """Scan up to max_scan listings for an associated OFFER whose unpaginated term count is in [2, 25]."""
    resp = client.search_listings(maxResults=max_scan)
    for summary in resp.get("listingSummaries", []):
        detail = client.get_listing(listingId=summary["listingId"])
        for entity in detail.get("associatedEntities", []):
            offer = entity.get("offer")
            if not offer:
                continue
            terms_resp = client.get_offer_terms(offerId=offer["offerId"], maxResults=25)
            if terms_resp.get("nextToken"):
                continue
            terms = terms_resp["offerTerms"]
            if len(terms) >= 2:
                return offer["offerId"], terms
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
