"""get-revenue-statistics-empty-for-new-webacl."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-revenue-statistics-empty-for-new-webacl"
GROUP = "data-plane"
SERVICES = ["wafv2"]

_SCOPE = "CLOUDFRONT"


def _wafv2_cloudfront_client(ctx):
    """CLOUDFRONT-scope WAF operations are only accepted against the us-east-1
    endpoint, regardless of the runner's configured region -- ctx.client's own
    ``region`` override pins it while keeping this target's real credentials
    and endpoint wiring."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevenueStatistics filtered on a never-created WebACL ARN returns no RevenuePathStatistics and no
    NextMarker; TOP_SOURCES_BY_REVENUE without GroupBy fails with WAFInvalidParameterException and
    the exact GroupBy message.
    """
    wafv2 = _wafv2_cloudfront_client(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    never_created_webacl_arn = (
        f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/"
        f"{ctx.unique_name('sim2real-behav-revstat-')}/{uuid.uuid4()}"
    )

    now = datetime.now(timezone.utc)
    try:
        resp = wafv2.get_revenue_statistics(
            StatisticType="TOP_PATHS_BY_REVENUE",
            TimeWindow={"StartTime": now - timedelta(hours=24), "EndTime": now},
            Scope=_SCOPE,
            Currency="USDC",
            Filters=[{"Name": "WebACLArn", "Values": [never_created_webacl_arn]}],
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "this account's automation role has no identity-based policy "
                "allowing wafv2:GetRevenueStatistics -- CLOUDFRONT-scope WAF/"
                "CloudFront monetization features are gated behind a separate "
                "grant this sandbox role doesn't hold"
            )
        raise

    assert resp.get("RevenuePathStatistics", []) == []
    assert not resp.get("NextMarker")

    # Positive control above already proves the account/role can call
    # GetRevenueStatistics at all. Break exactly one thing: GroupBy is required
    # when StatisticType is TOP_SOURCES_BY_REVENUE (model: "If GroupBy is
    # omitted, the request is rejected with a WAFInvalidParameterException").
    # GroupBy can never become optional for TOP_SOURCES_BY_REVENUE, so this is
    # an always-invalid-input negative with no restore leg.
    try:
        wafv2.get_revenue_statistics(
            StatisticType="TOP_SOURCES_BY_REVENUE",
            TimeWindow={"StartTime": now - timedelta(hours=24), "EndTime": now},
            Scope=_SCOPE,
            Currency="USDC",
            Filters=[{"Name": "WebACLArn", "Values": [never_created_webacl_arn]}],
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "WAFInvalidParameterException", (
            f"expected WAFInvalidParameterException for TOP_SOURCES_BY_REVENUE "
            f"with no GroupBy, got {code!r}"
        )
        message = err.response["Error"].get("Message")
        assert message == (
            "Error reason: GroupBy is required when StatisticType is TOP_SOURCES_BY_REVENUE., "
            "field: SCOPE_VALUE, parameter: GroupBy"
        ), message
    else:
        raise AssertionError(
            "GetRevenueStatistics with StatisticType=TOP_SOURCES_BY_REVENUE and "
            "no GroupBy succeeded -- GroupBy is required for that statistic type"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
