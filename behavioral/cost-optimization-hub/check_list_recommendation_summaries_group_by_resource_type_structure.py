"""list-recommendation-summaries-group-by-resource-type-structure."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-recommendation-summaries-group-by-resource-type-structure"
GROUP = "data-plane"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """ListRecommendationSummaries echoes groupBy ResourceType, then Region when asked, with a well-formed
    envelope (items list, 3-letter currencyCode, numeric totals) even when there are no recommendations."""
    # cost-optimization-hub's control plane exists only in us-east-1 (effective_region()).
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # ListRecommendationSummaries rejects with AccessDeniedException unless the account
    # is enrolled -- an account-global singleton this check does not own, so restore it
    # rather than leave it flipped for whichever check reads it next. A never-enrolled
    # account reports no item at all here (not an explicit "Inactive" row), which is
    # itself the account's default status.
    items = coh.list_enrollment_statuses().get("items", [])
    original_status = items[0]["status"] if items else "Inactive"
    if original_status != "Active":
        ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))
        coh.update_enrollment_status(status="Active")
        _poll_until(
            lambda: coh.list_enrollment_statuses()["items"][0],
            lambda item: item["status"] == "Active",
            timeout_s=30.0,
        )

    resp = _retry_while_not_enrolled(
        lambda: coh.list_recommendation_summaries(groupBy="ResourceType", maxResults=50),
        timeout_s=30.0,
    )

    assert resp["groupBy"] == "ResourceType", f"expected echo of ResourceType, got {resp['groupBy']!r}"
    assert isinstance(resp["items"], list), f"items should be a list, got {resp['items']!r}"
    assert isinstance(resp["currencyCode"], str) and len(resp["currencyCode"]) == 3, (
        f"expected a 3-letter currency code, got {resp['currencyCode']!r}"
    )
    assert isinstance(resp["estimatedTotalDedupedSavings"], (int, float)), (
        f"expected a numeric total, got {resp['estimatedTotalDedupedSavings']!r}"
    )
    for item in resp["items"]:
        assert isinstance(item["group"], str), f"expected str group, got {item['group']!r}"
        assert isinstance(item["recommendationCount"], int), (
            f"expected int recommendationCount, got {item['recommendationCount']!r}"
        )
        assert isinstance(item["estimatedMonthlySavings"], (int, float)), (
            f"expected numeric estimatedMonthlySavings, got {item['estimatedMonthlySavings']!r}"
        )

    # A stub that hardcodes "ResourceType" into the envelope would pass everything
    # above. Switching to the other documented dimension and requiring the echo to
    # move with it is the part a hardcoded responder cannot fake.
    resp_region = _retry_while_not_enrolled(
        lambda: coh.list_recommendation_summaries(groupBy="Region", maxResults=50),
        timeout_s=30.0,
    )
    assert resp_region["groupBy"] == "Region", (
        f"expected echo of Region, got {resp_region['groupBy']!r}"
    )
    assert resp_region["groupBy"] != resp["groupBy"], (
        "groupBy echo did not change between requests -- looks hardcoded"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_while_not_enrolled(call, *, timeout_s, interval_s=2.0):
    """Enrollment status flipping to Active does not always unblock the very next
    call -- this account is shared by concurrent checks that toggle the same
    account-global enrollment singleton, so a fresh AccessDeniedException here can be
    someone else's transient flip rather than this check's own enrollment failing to
    take. Retries ONLY that specific denial; any other error surfaces immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "AccessDeniedException" or "not enrolled" not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
