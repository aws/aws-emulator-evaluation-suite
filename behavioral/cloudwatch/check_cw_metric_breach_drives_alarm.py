"""cw-metric-breach-drives-alarm."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cw-metric-breach-drives-alarm"
GROUP = 'data-plane'
SERVICES = ['cloudwatch']

#: The default service-class budget bounds the evaluator wait; it is not an assertion on elapsed time.
_ALARM_WAIT_S = 240

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


def _expect_error(call, code, status, what):
    """Run call(); it must raise ClientError with this code and HTTP status.

    Returns the error; CloudWatch sends ResourceNotFound / ResourceNotFoundException with an empty
    message, which the caller grades.
    """
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert err.get("Code") == code, f"{what}: expected code {code!r}, got {err.get('Code')!r}"
        assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
        return err
    raise AssertionError(f"{what}: expected {code} (HTTP {status}), but the call succeeded")


def _alarm_transition(item):
    """The parsed HistoryData of a StateUpdate item, or {} when it is not JSON."""
    try:
        return json.loads(item.get("HistoryData") or "{}")
    except (ValueError, TypeError):
        return {}

# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Breaching PutMetricData moves an alarm to ALARM with a history item citing the breaching
    datapoint 100.0; once deleted, ListTagsForResource on its ARN (ResourceNotFoundException) and
    SetAlarmState (ResourceNotFound) fail with HTTP 404 and an empty message, and it is not listed."""
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "BreachMetric"
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def push_and_read():
        # Keep feeding breaching data each cycle so evaluation has fresh points.
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": 100.0, "Unit": "Count"}],
        )
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0][
            "StateValue"
        ]

    state = _poll_until(
        push_and_read,
        lambda s: s == "ALARM",
        timeout_s=_ALARM_WAIT_S,
        interval_s=10,
        description="alarm transitioning to ALARM from real metric data",
    )
    assert state == "ALARM", f"alarm did not reach ALARM: {state!r}"

    # Independent read: the evaluator recorded the transition with the datapoint it read.
    def alarm_items():
        resp = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")
        return [
            _alarm_transition(i)
            for i in resp.get("AlarmHistoryItems", [])
            if _alarm_transition(i).get("newState", {}).get("stateValue") == "ALARM"
        ]

    transitions = _poll_until(
        alarm_items, bool, timeout_s=60, interval_s=2,
        description="a StateUpdate history item with newState ALARM",
    )
    datapoints = [
        dp
        for t in transitions
        for dp in t.get("newState", {}).get("stateReasonData", {}).get("recentDatapoints", [])
    ]
    assert 100.0 in datapoints, (
        f"expected the ALARM transition's recentDatapoints to contain 100.0, got {datapoints!r}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    # Beat 1: CloudWatch has no read-by-name error; the tag read on the alarm ARN is the by-id read.
    refused = _expect_error(
        lambda: cw.list_tags_for_resource(ResourceARN=alarm_arn),
        "ResourceNotFoundException", 404, "ListTagsForResource on the deleted alarm",
    )
    expected_message = ""
    assert refused.get("Message", "") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Message", "")!r}'
    # Beat 2: the alarm is absent from a listing filtered to its own name.
    names = [a.get("AlarmName") for a in cw.describe_alarms(AlarmNamePrefix=alarm_name)["MetricAlarms"]]
    assert alarm_name not in names, f"deleted alarm still listed under its prefix: {names!r}"
    # Beat 3: a mutation on the dead name is refused.
    refused = _expect_error(
        lambda: cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="dead"),
        "ResourceNotFound", 404, "SetAlarmState on the deleted alarm",
    )
    expected_message = ""
    assert refused.get("Message", "") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Message", "")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
