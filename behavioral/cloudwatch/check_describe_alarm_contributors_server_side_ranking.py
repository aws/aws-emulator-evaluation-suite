"""describe-alarm-contributors-server-side-ranking."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-server-side-ranking"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """For a multi-time-series (Metrics Insights GROUP BY) alarm, DescribeAlarmContributors
    returns the server-computed set of individual time-series contributors currently in ALARM,
    without the client having to reconstruct that set from raw metric data itself.
    """
    

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavContribNS")
    metric_name = "HostLoad"
    dim_name = "Host"
    hosts = {
        ctx.unique_name("host-a-"): 300.0,
        ctx.unique_name("host-b-"): 200.0,
        ctx.unique_name("host-c-"): 100.0,
    }
    alarm_name = ctx.unique_name("sim2real-behav-contrib-alarm-")

    def _publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": metric_name, "Dimensions": [{"Name": dim_name, "Value": host}], "Value": value}
                for host, value in hosts.items()
            ],
        )

    _publish()

    # Real CloudWatch rejects a GROUP BY Metrics Insights alarm expression with no ORDER BY clause:
    # "Metrics expression that return multi time series are only allowed for MetricsInsights
    # expression with an ORDER BY clause". The ORDER BY ranking expression must repeat the SELECT
    # aggregate with EMPTY parentheses.
    query = (
        f'SELECT AVG({metric_name}) FROM SCHEMA("{namespace}", {dim_name}) GROUP BY {dim_name} '
        "ORDER BY AVG() DESC LIMIT 10"
    )
    try:
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Metrics=[{"Id": "m1", "Expression": query, "Period": 60, "ReturnData": True}],
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError" and "multi time series" in str(e):
            # This account/region rejects a GROUP BY Metrics Insights query on PutMetricAlarm
            # as a multi-time-series expression outright (the feature that
            # DescribeAlarmContributors is built on is apparently not available here), so the
            # precondition resource for this check cannot be constructed at all.
            raise AssertionError(
                "real AWS rejected the multi-time-series (GROUP BY) Metrics Insights alarm "
                f"itself with a server-side ValidationError ({e}); this account/region does not "
                "appear to support creating this alarm shape, so contributor ranking cannot be "
                "exercised"
            )
        raise
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Keep re-publishing fresh datapoints while polling, since alarm evaluation needs recent data
    # and Metrics Insights alarms only look at the last few hours / evaluation periods.
    deadline = time.monotonic() + 240.0
    contributors = None
    while time.monotonic() < deadline:
        _publish()
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if state == "ALARM":
            try:
                resp = cw.describe_alarm_contributors(AlarmName=alarm_name)
            except ClientError:
                resp = None
            if resp is not None and resp["AlarmContributors"]:
                contributors = resp["AlarmContributors"]
                break
        time.sleep(10)

    if not contributors:
        raise AssertionError(
            "the multi-time-series alarm never reached ALARM with contributor data within the "
            "240s poll budget (Metrics Insights alarm evaluation + custom metric ingestion "
            "latency); skipping rather than asserting a false negative",
        )

    # The response field is `ContributorAttributes` (per botocore's cloudwatch model and the
    # CloudWatch API reference); "AlarmContributorAttributes"/"Attributes" are not response fields.
    seen_hosts = set()
    for contributor in contributors:
        attrs = contributor.get("ContributorAttributes") or {}
        for value in attrs.values():
            if value in hosts:
                seen_hosts.add(value)
    # Every published host value (100.0-300.0) exceeds the alarm's threshold of 1.0, so every
    # group is breaching and the server-computed contributor set must be exactly all three hosts
    # -- not merely a non-empty subset, which a target returning a single contributor could
    # satisfy.
    assert seen_hosts == set(hosts.keys()), (
        f"expected all {len(hosts)} host contributors {sorted(hosts)} since every host's value "
        f"exceeds the alarm threshold of 1.0, got {sorted(seen_hosts)} in {contributors!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
