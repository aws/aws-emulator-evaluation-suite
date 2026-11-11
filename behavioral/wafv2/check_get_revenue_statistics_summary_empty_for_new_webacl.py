"""get-revenue-statistics-summary-empty-for-new-webacl."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-revenue-statistics-summary-empty-for-new-webacl"
GROUP = "data-plane"
SERVICES = ["wafv2"]

_SCOPE = "CLOUDFRONT"


def _wafv2_cloudfront_client(ctx):
    """CLOUDFRONT-scope WAF operations are only accepted against the us-east-1
    endpoint, regardless of the runner's configured region -- ctx.client's own
    `region` override pins it there while keeping the target's credentials
    and endpoint."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevenueStatisticsSummary filtered on a never-created WebACL ARN echoes Currency USDC and reports
    zero TotalAmount, UnverifiedAmount, VerifiedAmount, TotalMonetizeServed and TotalSettled.
    """
    wafv2 = _wafv2_cloudfront_client(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    never_created_webacl_arn = (
        f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/"
        f"{ctx.unique_name('sim2real-behav-revsum-')}/{uuid.uuid4()}"
    )

    now = datetime.now(timezone.utc)
    try:
        resp = wafv2.get_revenue_statistics_summary(
            TimeWindow={"StartTime": now - timedelta(hours=24), "EndTime": now},
            Scope=_SCOPE,
            Currency="USDC",
            Filters=[{"Name": "WebACLArn", "Values": [never_created_webacl_arn]}],
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "this account's automation role has no identity-based policy "
                "allowing wafv2:GetRevenueStatisticsSummary -- CLOUDFRONT-scope "
                "WAF/CloudFront monetization features are gated behind a "
                "separate grant this sandbox role doesn't hold"
            )
        raise

    breakdown = resp["RevenueBreakdown"]
    assert breakdown["Currency"] == "USDC", (
        f"expected echoed Currency USDC, got {breakdown['Currency']!r}"
    )
    assert float(breakdown["TotalAmount"]) == 0.0, (
        f"expected TotalAmount 0.0 for a never-created WebACL, got {breakdown['TotalAmount']!r}"
    )
    assert float(breakdown["UnverifiedAmount"]) == 0.0, (
        "expected UnverifiedAmount 0.0 for a never-created WebACL, got "
        f"{breakdown['UnverifiedAmount']!r}"
    )
    assert float(breakdown["VerifiedAmount"]) == 0.0, (
        f"expected VerifiedAmount 0.0 for a never-created WebACL, got {breakdown['VerifiedAmount']!r}"
    )
    assert breakdown["TotalMonetizeServed"] == 0, (
        "expected TotalMonetizeServed 0 for a never-created WebACL, got "
        f"{breakdown['TotalMonetizeServed']!r}"
    )
    assert breakdown["TotalSettled"] == 0, (
        f"expected TotalSettled 0 for a never-created WebACL, got {breakdown['TotalSettled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

