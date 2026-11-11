"""list-recommendations-check-identifier-filter-consistency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-check-identifier-filter-consistency"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


@tags("axis:rejection", "cap:c2", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListChecks and ListRecommendations both fail with AccessDeniedException "Access denied due to
    support level" for a caller without a Trusted Advisor support-level entitlement."""
    identity = ctx.client("sts").get_caller_identity()
    assert identity.get("Account"), (
        "STS get_caller_identity returned no Account -- credentials are unhealthy "
        "independent of Trusted Advisor, so a Trusted Advisor denial would prove nothing"
    )

    ta = ctx.client("trustedadvisor")

    def _assert_denied_for_support_level(label, call):
        try:
            call()
        except ClientError as err:
            error = err.response["Error"]
            assert error.get("Code") == "AccessDeniedException", (
                f"{label}: expected AccessDeniedException, got "
                f"{error.get('Code')!r} ({error.get('Message')!r})"
            )
            assert error.get("Message") == SUPPORT_LEVEL_DENIAL, (
                f"{label}: expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, "
                f"got {error.get('Message')!r}"
            )
            return
        raise AssertionError(
            f"{label}: expected Trusted Advisor to deny this account on support level "
            "(as it does for both ListChecks and ListRecommendations on this account's "
            "tier); the call succeeded instead"
        )

    _assert_denied_for_support_level("list_checks", lambda: ta.list_checks(maxResults=1))
    _assert_denied_for_support_level(
        "list_recommendations", lambda: ta.list_recommendations(maxResults=1)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
