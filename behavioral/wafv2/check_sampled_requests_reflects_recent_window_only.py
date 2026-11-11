"""sampled-requests-reflects-recent-window-only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sampled-requests-reflects-recent-window-only"
GROUP = "visibility-timeout-ttl"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSampledRequests echoes an in-range TimeWindow StartTime unchanged and clamps a StartTime
    older than three hours to roughly now minus three hours.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_GetSampledRequests.html
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-sampled-")
    scope = "REGIONAL"
    rule_metric_name = "sample-rule"
    rules = [
        {
            "Name": "sample-rule",
            "Priority": 1,
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            "Action": {"Count": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": rule_metric_name,
            },
        }
    ]
    acl_vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=rules,
        VisibilityConfig=acl_vis,
        Tags=[{"Key": "Team", "Value": "sim2real"}],
    )
    summary = created["Summary"]
    acl_id = summary["Id"]
    acl_arn = summary["ARN"]

    def _cleanup():
        try:
            cur = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    now = datetime.now(timezone.utc)

    # Positive control: an in-range window (last 1 hour) is not clamped.
    in_range_start = now - timedelta(hours=1)
    resp_in_range = wafv2.get_sampled_requests(
        WebAclArn=acl_arn,
        RuleMetricName=rule_metric_name,
        Scope=scope,
        TimeWindow={"StartTime": in_range_start, "EndTime": now},
        MaxItems=100,
    )
    assert isinstance(resp_in_range.get("SampledRequests"), list), (
        f"SampledRequests missing or not a list: {resp_in_range.get('SampledRequests')!r}"
    )
    returned_start_in_range = resp_in_range["TimeWindow"]["StartTime"]
    drift_in_range = abs((returned_start_in_range - in_range_start).total_seconds())
    assert drift_in_range <= 30, (
        f"in-range StartTime was altered: requested {in_range_start}, got {returned_start_in_range}"
    )

    # A StartTime far outside the documented 3-hour range, EndTime unchanged.
    out_of_range_start = now - timedelta(hours=10)
    resp_out_of_range = wafv2.get_sampled_requests(
        WebAclArn=acl_arn,
        RuleMetricName=rule_metric_name,
        Scope=scope,
        TimeWindow={"StartTime": out_of_range_start, "EndTime": now},
        MaxItems=100,
    )
    returned_start_clamped = resp_out_of_range["TimeWindow"]["StartTime"]

    drift_from_requested = abs((returned_start_clamped - out_of_range_start).total_seconds())
    assert drift_from_requested > 3600, (
        "StartTime older than 3 hours was echoed back unclamped: "
        f"requested {out_of_range_start}, got {returned_start_clamped}"
    )

    expected_clamp = now - timedelta(hours=3)
    drift_from_clamp = abs((returned_start_clamped - expected_clamp).total_seconds())
    assert drift_from_clamp <= 120, (
        f"clamped StartTime not within tolerance of now-3h: expected ~{expected_clamp}, "
        f"got {returned_start_clamped}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
