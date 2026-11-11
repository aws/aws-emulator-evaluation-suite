"""next-token-reuse-deterministic."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "next-token-reuse-deterministic"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing the same nextToken twice returns the same page contents both times."""
    client = ctx.client("bcm-recommended-actions")

    first_page = client.list_recommended_actions(maxResults=1)
    token = first_page.get("nextToken")
    if not token:
        raise AssertionError(
            "this account currently has fewer than 2 recommended actions, so "
            "ListRecommendedActions never returns a nextToken to exercise reuse "
            "determinism against; would close with a test account seeded with "
            "multiple recommended-action-triggering conditions (e.g. an expiring RI "
            "plus an unresolved cost anomaly)."
        )

    page_a = client.list_recommended_actions(nextToken=token)["recommendedActions"]
    page_b = client.list_recommended_actions(nextToken=token)["recommendedActions"]

    ids_a = [a["id"] for a in page_a]
    ids_b = [a["id"] for a in page_b]
    assert ids_a == ids_b, "reusing the same nextToken produced different results"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
