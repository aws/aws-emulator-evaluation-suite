"""alarm-missing-data-and-m-of-n-describe-views-echo-the-evaluation-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarm-missing-data-and-m-of-n-describe-views-echo-the-evaluation-config"
GROUP = "alarms"
SERVICES = ["cloudwatch"]

_EVAL_FIELDS = ("Namespace", "MetricName", "Statistic", "Period", "Unit", "EvaluationPeriods",
                "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData",
                "ActionsEnabled", "AlarmDescription")


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DescribeAlarms and DescribeAlarmsForMetric echo the same non-default evaluation config,
    and both views move together after a full-replace PutMetricAlarm.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEcho")
    alarm = ctx.unique_name("sim2real-echo-")
    dims = [{"Name": "Service", "Value": "checkout"}, {"Name": "Stage", "Value": "prod"}]

    first = dict(
        AlarmName=alarm, Namespace=namespace, MetricName="Latency", Dimensions=dims,
        Statistic="Average", Period=120, Unit="Seconds", EvaluationPeriods=4, DatapointsToAlarm=3,
        Threshold=12.5, ComparisonOperator="LessThanOrEqualToThreshold", TreatMissingData="ignore",
        ActionsEnabled=False, AlarmDescription="sim2real echo: 3 of 4, ignore",
    )
    cw.put_metric_alarm(Tags=[{"Key": "sim2real", "Value": CHECK}], **first)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    _assert_views(cw, alarm, first, "after create")

    second = dict(first, EvaluationPeriods=5, DatapointsToAlarm=2, Threshold=7.25,
                  TreatMissingData="breaching", AlarmDescription="sim2real echo: 2 of 5, breaching")
    cw.put_metric_alarm(**second)
    _assert_views(cw, alarm, second, "after full replace")


def _by_name(cw, alarm):
    found = []
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]
    ):
        found.extend(a for a in page.get("MetricAlarms", []) if a["AlarmName"] == alarm)
    assert len(found) == 1, f"DescribeAlarms returned {len(found)} alarms named {alarm!r}"
    return found[0]


def _by_metric(cw, alarm, sent):
    resp = cw.describe_alarms_for_metric(
        Namespace=sent["Namespace"], MetricName=sent["MetricName"], Dimensions=sent["Dimensions"],
        Statistic=sent["Statistic"], Period=sent["Period"], Unit=sent["Unit"],
    )
    found = [a for a in resp.get("MetricAlarms", []) if a["AlarmName"] == alarm]
    assert len(found) == 1, (
        f"DescribeAlarmsForMetric over the alarm's own metric identity returned "
        f"{[a['AlarmName'] for a in resp.get('MetricAlarms', [])]!r}, expected {alarm!r} once"
    )
    return found[0]


def _assert_views(cw, alarm, sent, when):
    named, metric = _by_name(cw, alarm), _by_metric(cw, alarm, sent)
    for view_name, view in (("DescribeAlarms", named), ("DescribeAlarmsForMetric", metric)):
        for field in _EVAL_FIELDS:
            assert view.get(field) == sent[field], (
                f"{when}: {view_name} echoes {field}={view.get(field)!r}, PutMetricAlarm sent "
                f"{sent[field]!r}"
            )
        got_dims = sorted((d["Name"], d["Value"]) for d in view.get("Dimensions", []))
        want_dims = sorted((d["Name"], d["Value"]) for d in sent["Dimensions"])
        assert got_dims == want_dims, f"{when}: {view_name} echoes Dimensions {got_dims!r}"
    disagree = {
        f: (named.get(f), metric.get(f))
        for f in _EVAL_FIELDS + ("AlarmArn", "Dimensions", "AlarmConfigurationUpdatedTimestamp")
        if named.get(f) != metric.get(f)
    }
    assert not disagree, f"{when}: the two read views disagree on {disagree!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
