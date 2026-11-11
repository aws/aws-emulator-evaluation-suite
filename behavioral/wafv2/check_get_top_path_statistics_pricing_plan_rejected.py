"""get-top-path-statistics-pricing-plan-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-top-path-statistics-pricing-plan-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTopPathStatisticsByTraffic on a fresh CLOUDFRONT web ACL either reports zero traffic and no
    path entries, or, behind a flat-rate plan excluding the feature, fails with
    WAFFeatureNotIncludedInPricingPlanException while GetSampledRequests still succeeds.
    """
    wafv2 = _cloudfront_wafv2_client(ctx)
    web_acl_name = ctx.unique_name("sim2real-behav-wacl-")
    created = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": web_acl_name,
        },
        Rules=[
            {
                "Name": "sample-rule",
                "Priority": 0,
                "Action": {"Count": {}},
                "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "sample-rule",
                },
            }
        ],
    )["Summary"]
    web_acl_arn = created["ARN"]
    web_acl_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_web_acl(wafv2, web_acl_name, web_acl_id))

    now = datetime.now(timezone.utc)
    window = {"StartTime": now - timedelta(hours=1), "EndTime": now}

    try:
        stats = wafv2.get_top_path_statistics_by_traffic(
            WebAclArn=web_acl_arn,
            Scope="CLOUDFRONT",
            TimeWindow=window,
            Limit=10,
            NumberOfTopTrafficBotsPerPath=5,
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "WAFFeatureNotIncludedInPricingPlanException", f"got {code!r} instead"
        # A same-family read must still succeed: only this feature is pricing-gated.
        sampled = wafv2.get_sampled_requests(
            WebAclArn=web_acl_arn,
            RuleMetricName="sample-rule",
            Scope="CLOUDFRONT",
            TimeWindow=window,
            MaxItems=1,
        )
        assert "PopulationSize" in sampled, f"positive control failed: {sampled!r}"
        return

    # A web ACL created directly via CreateWebACL is not enrolled in any flat-rate plan, so the
    # call succeeds and a trafficless ACL must report zero statistics.
    total_request_count = stats["TotalRequestCount"]
    path_stats = stats["PathStatistics"]
    assert total_request_count == 0, (
        f"expected 0 requests for a fresh, trafficless CLOUDFRONT web ACL, "
        f"got TotalRequestCount={total_request_count!r}"
    )
    assert path_stats == [], (
        f"expected no path statistics for a fresh, trafficless web ACL, got {path_stats!r}"
    )


def _cloudfront_wafv2_client(ctx):
    """CLOUDFRONT-scope WAFv2 operations are only valid against the us-east-1 endpoint."""
    return ctx.client("wafv2", region="us-east-1")


def _safe_delete_web_acl(wafv2, name, web_acl_id):
    try:
        lock_token = wafv2.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
        wafv2.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


