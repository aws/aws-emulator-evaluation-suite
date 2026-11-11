"""list-recommendations-for-resource-unknown-arn-returns-empty."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-for-resource-unknown-arn-returns-empty"
GROUP = "error-semantics"
SERVICES = ["trustedadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRecommendationsForResource returns an empty list for a well-formed unknown resource ARN;
    without a support-level entitlement it fails with AccessDeniedException "Access denied due to
    support level".
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_instance_arn = (
        f"arn:aws:ec2:{ctx.region}:{account_id}:instance/i-0000000000sim2real"
    )
    ta = ctx.client("trustedadvisor")
    try:
        resp = ta.list_recommendations_for_resource(awsResourceArn=fake_instance_arn)
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "AccessDeniedException", (
            f"expected AccessDeniedException for an account without Trusted Advisor "
            f"entitlement, got {error['Code']!r}: {error.get('Message')!r}"
        )
        assert error.get("Message") == "Access denied due to support level", (
            "expected the entitlement-gate message AWS actually returns, "
            f"got {error.get('Message')!r} -- this account/account tier may no longer be "
            "gated the way this check assumes"
        )
        return
    assert resp.get("recommendationForResourceSummaries", []) == [], (
        "expected an empty list for an unrecognized/nonexistent resource ARN, "
        "not an error and not a non-empty result"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
