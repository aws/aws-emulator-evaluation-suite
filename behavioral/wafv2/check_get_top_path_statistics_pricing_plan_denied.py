"""get-top-path-statistics-pricing-plan-denied."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-top-path-statistics-pricing-plan-denied"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTopPathStatisticsByTraffic with Scope=CLOUDFRONT on a REGIONAL web ACL fails with
    WAFInvalidParameterException and the exact invalid-ARN message; with Scope=REGIONAL the same web
    ACL reports TotalRequestCount 0 and no PathStatistics.
    """
    wafv2 = ctx.client("wafv2")
    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    webacl = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    webacl_id = webacl["Id"]
    webacl_arn = webacl["ARN"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=webacl["LockToken"]
        )
    )

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)

    # Negative: Scope=CLOUDFRONT with a REGIONAL web ACL's ARN. The RESOURCE_ARN field fails
    # validation for that scope, so AWS answers WAFInvalidParameterException.
    code, message = _error(
        lambda: wafv2.get_top_path_statistics_by_traffic(
            WebAclArn=webacl_arn,
            Scope="CLOUDFRONT",
            TimeWindow={"StartTime": start, "EndTime": end},
            Limit=10,
            NumberOfTopTrafficBotsPerPath=5,
        )
    )
    assert code == "WAFInvalidParameterException", f"expected WAFInvalidParameterException, got {code!r}"
    assert message == (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        "information separated by colons or slashes., field: RESOURCE_ARN, "
        f"parameter: {webacl_arn}"
    ), message

    # Positive control, same file: the matching Scope=REGIONAL call on the same web ACL
    # succeeds and reports the real (zero) traffic state, proving the rejection above is the
    # scope/ARN-mismatch check, not an account-wide failure of the operation.
    control = wafv2.get_top_path_statistics_by_traffic(
        WebAclArn=webacl_arn,
        Scope="REGIONAL",
        TimeWindow={"StartTime": start, "EndTime": end},
        Limit=10,
        NumberOfTopTrafficBotsPerPath=5,
    )
    assert control["TotalRequestCount"] == 0, f"expected 0 requests on a fresh web ACL, got {control['TotalRequestCount']!r}"
    assert control["PathStatistics"] == [], f"expected no path entries on a fresh web ACL, got {control['PathStatistics']!r}"


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

