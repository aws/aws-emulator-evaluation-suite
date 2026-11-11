"""result-ids-unique-within-single-page."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "result-ids-unique-within-single-page"
GROUP = "contract"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single ListRecommendedActions page never contains the same action id
    twice, even when the page is large enough to hold the account's entire
    result set (maxResults=1000, the documented maximum)."""
    client = ctx.client("bcm-recommended-actions")
    resp = client.list_recommended_actions(maxResults=1000)
    actions = resp["recommendedActions"]
    if not actions:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service to manufacture one -- needs a sandbox account with at least one "
            "naturally-occurring action, or a same-id duplicate within the page can "
            "never be observed"
        )

    ids = [a["id"] for a in actions]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, (
        f"expected {len(ids)} distinct ids, got {len(set(ids))} distinct values -- "
        f"duplicated ids in a single page: {duplicates}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
