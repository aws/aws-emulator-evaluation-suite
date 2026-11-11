"""list-checks-pillar-filter-consistency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-pillar-filter-consistency"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _assert_support_level_denial(err: ClientError) -> None:
    """The account's support plan, not IAM or the pillar argument, caused this denial."""
    code = err.response["Error"]["Code"]
    message = err.response["Error"].get("Message")
    assert (code, message) == ("AccessDeniedException", SUPPORT_LEVEL_DENIAL), (
        "expected the Trusted Advisor support-level entitlement gate, got "
        f"code={code!r} message={message!r}"
    )


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChecks(pillar=cost_optimizing) returns exactly the catalog's cost_optimizing checks;
    without a support-level entitlement, both the unfiltered and the pillar-filtered call fail with
    AccessDeniedException "Access denied due to support level".
    """
    ta = ctx.client("trustedadvisor")
    try:
        all_checks = ta.list_checks(maxResults=200).get("checkSummaries", [])
    except ClientError as err:
        _assert_support_level_denial(err)
        try:
            ta.list_checks(pillar="cost_optimizing", maxResults=200)
        except ClientError as err2:
            _assert_support_level_denial(err2)
            return
        raise AssertionError(
            "unfiltered ListChecks was denied for lacking Trusted Advisor support-level "
            "entitlement, but ListChecks(pillar='cost_optimizing') succeeded - the "
            "entitlement gate is inconsistent across filter forms"
        )

    expected_ids = {c["id"] for c in all_checks if "cost_optimizing" in c["pillars"]}
    assert len(expected_ids) > 0, "expected at least one cost_optimizing check in the catalog"

    filtered = ta.list_checks(pillar="cost_optimizing", maxResults=200).get("checkSummaries", [])
    filtered_ids = {c["id"] for c in filtered}
    for c in filtered:
        assert "cost_optimizing" in c["pillars"], (
            f"check {c['id']} returned by pillar filter but pillars={c['pillars']}"
        )
    assert filtered_ids == expected_ids, (
        f"pillar filter mismatch: filtered={sorted(filtered_ids)} expected={sorted(expected_ids)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
