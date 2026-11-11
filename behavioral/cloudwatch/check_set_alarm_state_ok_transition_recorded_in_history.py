"""set-alarm-state-ok-transition-recorded-in-history."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "set-alarm-state-ok-transition-recorded-in-history"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

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
    """Run call(); it must raise ClientError with this code and the HTTP class of status.

    Returns the error; CloudWatch sends ResourceNotFound / ResourceNotFoundException with an empty
    message, which the caller grades.
    """
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert err.get("Code") == code, f"{what}: expected code {code!r}, got {err.get('Code')!r}"
        assert isinstance(got_status, int) and got_status // 100 == status // 100, (
            f"{what}: expected HTTP {status // 100}xx, got {got_status!r}"
        )
        return err
    raise AssertionError(f"{what}: expected {code} (HTTP {status}), but the call succeeded")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Transitioning ALARM->OK is reflected in both DescribeAlarms and DescribeAlarmHistory."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="go alarm")

    def probe_alarm():
        return cw.describe_alarms(AlarmNames=[alarm_name])

    _poll_until(
        probe_alarm,
        lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["StateValue"] == "ALARM",
        timeout_s=20,
        interval_s=2,
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="go ok")

    resp = _poll_until(
        probe_alarm,
        lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["StateValue"] == "OK",
        timeout_s=20,
        interval_s=2,
    )
    actual_state = resp["MetricAlarms"][0]["StateValue"]
    assert actual_state == "OK", f"expected StateValue OK after transition, got {actual_state!r}"
    alarm_arn = resp["MetricAlarms"][0].get("AlarmArn")
    expected_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{alarm_name}"
    assert alarm_arn == expected_arn, f"expected AlarmArn {expected_arn!r}, got {alarm_arn!r}"

    def probe_history():
        return cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate"
        )

    hist = _poll_until(
        probe_history, lambda r: len(r.get("AlarmHistoryItems", [])) >= 2, timeout_s=20, interval_s=2
    )
    items = hist["AlarmHistoryItems"]
    assert len(items) >= 2, f"expected at least 2 state-update history items, got {len(items)}"

    ok_transition = None
    for item in items:
        try:
            data = json.loads(item.get("HistoryData", "{}"))
        except (ValueError, TypeError):
            continue
        if data.get("newState", {}).get("stateValue") == "OK":
            ok_transition = data
            break

    assert ok_transition is not None, (
        f"no StateUpdate history item recorded a transition to OK: {items}"
    )
    old_state = ok_transition["oldState"]["stateValue"]
    assert old_state == "ALARM", (
        f"the recorded OK transition's oldState should be ALARM, got {old_state!r}"
    )
    new_reason = ok_transition["newState"]["stateReason"]
    assert new_reason == "go ok", (
        f"the recorded OK transition's stateReason should be 'go ok', got {new_reason!r}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    # Beat 1: CloudWatch has no read-by-name error; DescribeAlarms by the exact name returns nothing.
    by_name = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert by_name == [], f"DescribeAlarms(AlarmNames=[{alarm_name!r}]) still returns the deleted alarm: {by_name!r}"
    # Beat 2: the alarm is absent from a listing filtered to its own name.
    listed = cw.describe_alarms(AlarmNamePrefix=alarm_name)["MetricAlarms"]
    names = [a.get("AlarmName") for a in listed]
    assert alarm_name not in names, f"deleted alarm still listed under its prefix: {names!r}"
    # Beat 3: a mutation on the dead name is refused.
    refused = _expect_error(
        lambda: cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="dead"),
        "ResourceNotFound", 404, "SetAlarmState on the deleted alarm",
    )
    expected_message = ""
    assert refused.get("Message", "") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Message", "")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
