"""list-recommendations-status-partition-invariant."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-status-partition-invariant"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"
INVALID_STATUS_MESSAGE = (
    "1 validation error detected: Value 'not-a-real-status' at 'status' failed to satisfy "
    "constraint: Member must satisfy enum value set: [error, warning, ok]"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRecommendations with an invalid status fails with ValidationException and the exact
    message, while a well-formed call fails with AccessDeniedException "Access denied due to support
    level" for a caller without a support-level entitlement.
    """
    ta = ctx.client("trustedadvisor")

    try:
        ta.list_recommendations(status="not-a-real-status", maxResults=1)
        raise AssertionError(
            "expected an invalid status enum value to be rejected by the service, "
            "but the call succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"positive control failed: expected ValidationException for a malformed "
            f"status filter (proving the request reaches the service), got {code!r}"
        )
        message = err.response["Error"].get("Message")
        assert message == INVALID_STATUS_MESSAGE, (
            f"expected the exact enum-violation message {INVALID_STATUS_MESSAGE!r}, got {message!r}"
        )

    try:
        resp = ta.list_recommendations(maxResults=100)
        raise AssertionError(
            "ListRecommendations unexpectedly succeeded on an account with no "
            f"Trusted Advisor API entitlement; got "
            f"{len(resp.get('recommendationSummaries', []))} recommendation(s)"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "AccessDeniedException", (
            f"expected AccessDeniedException for a well-formed ListRecommendations "
            f"call on a support-plan-gated account, got {code!r} ({message!r})"
        )
        assert message == SUPPORT_LEVEL_DENIAL, (
            f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
