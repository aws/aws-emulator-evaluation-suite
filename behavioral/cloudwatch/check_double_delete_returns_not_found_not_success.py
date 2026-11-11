"""double-delete-returns-not-found-not-success."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "double-delete-returns-not-found-not-success"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)

_INSIGHT_RULE_DEFINITION = json.dumps(
    {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "AggregateOn": "Count",
        "LogGroupNames": ["/aws/lambda/*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.requestId"], "Filters": []},
    }
)


def _dashboard_body(marker: str) -> str:
    return json.dumps(
        {
            "widgets": [
                {
                    "type": "text",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 3,
                    "properties": {"markdown": marker},
                }
            ]
        }
    )


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_anomaly_detector_if_present(cw, spec):
    """Teardown: the check deletes the detector itself, so not-found here is expected."""
    try:
        cw.delete_anomaly_detector(**spec)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """A second delete is a no-op success for alarms, dashboards, metric streams, mute rules and
    insight rules, while DeleteAnomalyDetector fails with ResourceNotFoundException; in every
    case the resource stays gone."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- DeleteAlarms: idempotent no-op on a second delete ---
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-dd-")
    cw.put_metric_alarm(AlarmName=alarm_name, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))
    cw.delete_alarms(AlarmNames=[alarm_name])
    # A second delete is a no-op success: any ClientError propagates and fails the check.
    cw.delete_alarms(AlarmNames=[alarm_name])
    still_gone = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
    assert still_gone == [], "a double-deleted alarm must not have been resurrected"

    # --- DeleteDashboards: idempotent no-op on a second delete ---
    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-dd-")
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_dashboard_body("double-delete"))
    ctx.on_cleanup(lambda _n=dash_name: cw.delete_dashboards(DashboardNames=[_n]))
    cw.delete_dashboards(DashboardNames=[dash_name])
    cw.delete_dashboards(DashboardNames=[dash_name])
    not_found_code, not_found_msg = _err(lambda: cw.get_dashboard(DashboardName=dash_name))
    assert not_found_code == "ResourceNotFound", (
        f"a double-deleted dashboard must genuinely not exist, got {not_found_code}"
    )
    assert not_found_msg == f"Dashboard {dash_name} does not exist", f"unexpected GetDashboard message {not_found_msg!r}"

    # --- DeleteMetricStream: idempotent no-op on a second delete ---
    # A fabricated Firehose/role is accepted -- CloudWatch does not eagerly resolve them.
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-mstream-dd-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{account}:role/{stream_name}"
    ctx.on_cleanup(lambda _n=stream_name: cw.delete_metric_stream(Name=_n))
    cw.put_metric_stream(Name=stream_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")

    def stream_running():
        return cw.get_metric_stream(Name=stream_name)["State"]

    _poll_until(stream_running, lambda s: s == "running", timeout_s=30, interval_s=2)
    cw.delete_metric_stream(Name=stream_name)
    cw.delete_metric_stream(Name=stream_name)
    gone_code, gone_msg = _err(lambda: cw.get_metric_stream(Name=stream_name))
    assert gone_code == "ResourceNotFoundException", (
        f"a double-deleted metric stream must genuinely not exist, got {gone_code}"
    )
    # GetMetricStream answers not-found with an empty message.
    assert gone_msg == "", f"unexpected GetMetricStream message {gone_msg!r}"

    # --- DeleteAlarmMuteRule: idempotent no-op on a second delete ---
    mute_alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-mute-dd-")
    cw.put_metric_alarm(AlarmName=mute_alarm, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda _n=mute_alarm: cw.delete_alarms(AlarmNames=[_n]))
    mute_name = ctx.unique_name("sim2real-behav-cwprobe-mute-dd-")
    cw.put_alarm_mute_rule(
        Name=mute_name,
        Rule={"Schedule": {"Expression": "at(2030-01-01T00:00)", "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [mute_alarm]},
    )
    ctx.on_cleanup(lambda _n=mute_name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=_n))

    def mute_visible():
        return cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name).get("Name")

    _poll_until(mute_visible, lambda n: n == mute_name, timeout_s=30, interval_s=2)
    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_name)
    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_name)
    gone_code, gone_msg = _err(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name))
    assert gone_code == "ResourceNotFoundException", (
        f"a double-deleted alarm mute rule must genuinely not exist, got {gone_code}"
    )
    # GetAlarmMuteRule answers not-found with an empty message.
    assert gone_msg == "", f"unexpected GetAlarmMuteRule message {gone_msg!r}"

    # --- DeleteAnomalyDetector: genuinely enforces not-found on a second delete ---
    ad_namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-dd-")
    ad_metric = "DoubleDeleteMetric"
    cw.put_anomaly_detector(Namespace=ad_namespace, MetricName=ad_metric, Stat="Average")
    ad_spec = dict(Namespace=ad_namespace, MetricName=ad_metric, Stat="Average")
    ctx.on_cleanup(lambda _s=dict(ad_spec): _delete_anomaly_detector_if_present(cw, _s))

    def ad_visible():
        return cw.describe_anomaly_detectors(Namespace=ad_namespace, MetricName=ad_metric).get(
            "AnomalyDetectors", []
        )

    _poll_until(ad_visible, lambda ds: len(ds) > 0, timeout_s=30, interval_s=2)
    cw.delete_anomaly_detector(**ad_spec)
    code, msg = _err(lambda: cw.delete_anomaly_detector(**ad_spec))
    assert code == "ResourceNotFoundException", (
        f"DeleteAnomalyDetector: expected ResourceNotFoundException on a second delete, got {code}"
    )
    assert msg == "Anomaly detector not found", f"unexpected DeleteAnomalyDetector message {msg!r}"
    still_gone_ad = ad_visible()
    assert still_gone_ad == [], (
        f"a double-deleted anomaly detector must not have been resurrected, got {still_gone_ad}"
    )

    # --- DeleteInsightRules: also idempotent -- Failures stays empty for an
    # already-deleted (merely absent) rule name.
    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-dd-")
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=_INSIGHT_RULE_DEFINITION)
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))

    def rule_visible():
        r = cw.describe_insight_rules().get("InsightRules", [])
        return any(x["Name"] == rule_name for x in r)

    _poll_until(rule_visible, lambda v: v, timeout_s=30, interval_s=2)
    first = cw.delete_insight_rules(RuleNames=[rule_name])
    assert first.get("Failures", []) == [], f"expected no Failures deleting a real rule, got {first}"
    second = cw.delete_insight_rules(RuleNames=[rule_name])
    assert second.get("Failures", []) == [], (
        f"DeleteInsightRules: expected a second delete of an already-deleted rule to be a "
        f"clean idempotent no-op (empty Failures), got {second}"
    )
    still_gone_rules = cw.describe_insight_rules().get("InsightRules", [])
    assert not any(r["Name"] == rule_name for r in still_gone_rules), (
        "a double-deleted insight rule must not have been resurrected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
