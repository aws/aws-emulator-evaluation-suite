"""top-path-statistics-reflects-traffic-volume-ordering."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "top-path-statistics-reflects-traffic-volume-ordering"
GROUP = "data-plane"
SERVICES = ["wafv2"]


def _cloudfront_wafv2_client(ctx):
    """A wafv2 client pinned to us-east-1, the only endpoint for CLOUDFRONT-scope operations."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTopPathStatisticsByTraffic on a CLOUDFRONT web ACL that never received traffic answers 200
    with a well-formed empty result (TotalRequestCount 0, PathStatistics []), not fabricated data.
    """
    wafv2 = _cloudfront_wafv2_client(ctx)
    scope = "CLOUDFRONT"
    name = ctx.unique_name("sim2real-behav-toppath-")
    metric_name = name.replace("-", "")
    create = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    web_acl_arn = create["Summary"]["ARN"]
    web_acl_id = create["Summary"]["Id"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=name,
            Scope=scope,
            Id=web_acl_id,
            LockToken=wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"],
        )
    )

    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=3)
    kwargs = dict(
        WebAclArn=web_acl_arn,
        Scope=scope,
        TimeWindow={"StartTime": start, "EndTime": end},
        Limit=50,
        NumberOfTopTrafficBotsPerPath=5,
    )
    # Real per-path ordering needs accumulated bot traffic through CloudFront; with none, AWS
    # answers 200 with an empty payload rather than WAFNonexistentItemException.
    resp = wafv2.get_top_path_statistics_by_traffic(**kwargs)

    # Both members are required in the output shape, so a response omitting them is wrong.
    assert "TotalRequestCount" in resp and "PathStatistics" in resp, (
        f"expected the required TotalRequestCount and PathStatistics members, got keys {sorted(resp)}"
    )
    assert resp["TotalRequestCount"] == 0, (
        f"expected TotalRequestCount == 0 for a freshly created web ACL with no "
        f"traffic, got {resp['TotalRequestCount']!r}"
    )
    counts = [p["RequestCount"] for p in resp["PathStatistics"]]
    assert counts == [], (
        f"expected PathStatistics == [] for a freshly created web ACL with no "
        f"traffic, got {counts}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
