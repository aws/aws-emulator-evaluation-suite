"""get-offer-terms-pagination-respects-max-results."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-offer-terms-pagination-respects-max-results"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating GetOfferTerms one term at a time with maxResults=1 yields the same set of terms,
    in the same total count, as a single call requesting the maximum page size."""
    md = ctx.client("marketplace-discovery")
    offer_id, full = _find_offer_with_multiple_terms(md)
    if offer_id is None:
        raise AssertionError(
            "no scanned listing's default offer (across up to 20 listing summaries) exposes 2+ "
            "terms; pagination cannot be meaningfully exercised"
        )

    paged = []
    token = None
    for _ in range(15):
        kwargs = {"offerId": offer_id, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = md.get_offer_terms(**kwargs)
        assert len(resp["offerTerms"]) <= 1, (
            f"maxResults=1 but page returned {len(resp['offerTerms'])} terms"
        )
        paged.extend(resp["offerTerms"])
        token = resp.get("nextToken")
        if not token:
            break

    assert len(paged) == len(full), (
        f"paginated collection returned {len(paged)} terms, unpaginated call returned {len(full)}"
    )
    paged_json = sorted(json.dumps(t, sort_keys=True, default=str) for t in paged)
    full_json = sorted(json.dumps(t, sort_keys=True, default=str) for t in full)
    assert paged_json == full_json, "paginated terms are not the same set as the unpaginated terms"


def _find_offer_with_multiple_terms(md, max_scan: int = 20):
    resp = md.search_listings(maxResults=max_scan)
    seen_offer_ids = set()
    for summary in resp["listingSummaries"]:
        detail = md.get_listing(listingId=summary["listingId"])
        for entity in detail["associatedEntities"]:
            offer = entity.get("offer")
            if not offer or offer["offerId"] in seen_offer_ids:
                continue
            seen_offer_ids.add(offer["offerId"])
            terms = md.get_offer_terms(offerId=offer["offerId"], maxResults=25)["offerTerms"]
            if len(terms) >= 2:
                return offer["offerId"], terms
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
