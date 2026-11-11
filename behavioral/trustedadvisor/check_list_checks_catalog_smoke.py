"""list-checks-catalog-smoke."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-catalog-smoke"
GROUP = "smoke"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


@tags(
    "axis:happy-path",
    "cap:c5",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """ListChecks returns a non-empty catalog of well-formed checks (id, check ARN, name, description,
    pillars, awsServices, source); without a support-level entitlement, ListChecks and
    ListRecommendations both fail with AccessDeniedException "Access denied due to support level"."""
    ta = ctx.client("trustedadvisor")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    assert account_id, "sts get-caller-identity returned no account id - credentials are unhealthy"

    try:
        resp = ta.list_checks(maxResults=50)
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "AccessDeniedException", (
            f"expected AccessDeniedException for a caller lacking a TA support plan, got {error!r}"
        )
        message = error.get("Message")
        assert message == SUPPORT_LEVEL_DENIAL, (
            f"expected the refusal message {SUPPORT_LEVEL_DENIAL!r}, got {message!r}"
        )

        recs_code, recs_msg = _error(lambda: ta.list_recommendations(maxResults=1))
        assert recs_code == "AccessDeniedException", (
            f"expected ListRecommendations to be denied identically (an account-wide "
            f"entitlement gate, not a permission gap on ListChecks alone), got {recs_code!r}"
        )
        assert recs_msg == SUPPORT_LEVEL_DENIAL, (
            f"expected ListRecommendations' denial message {SUPPORT_LEVEL_DENIAL!r}, got {recs_msg!r}"
        )
        return

    checks = resp.get("checkSummaries", [])
    assert len(checks) > 0, "expected a non-empty Trusted Advisor check catalog"
    for c in checks[:10]:
        assert c["id"]
        assert c["arn"].startswith("arn:") and ":trustedadvisor:::check/" in c["arn"]
        assert c["name"]
        assert c["description"]
        assert isinstance(c["pillars"], list) and len(c["pillars"]) >= 1
        assert isinstance(c["awsServices"], list)
        assert c["source"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
