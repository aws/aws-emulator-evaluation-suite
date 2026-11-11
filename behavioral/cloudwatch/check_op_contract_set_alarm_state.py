"""op-contract-set-alarm-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-set-alarm-state"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState forcibly drives an alarm's StateValue/StateReason and is recorded in history; invalid input is rejected without side effect."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-sas-ns-")
    name = ctx.unique_name("sim2real-behav-alarm-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=ns,
        MetricName="ErrorRate",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=5.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    initial = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    # new metric alarms always start here
    assert initial["StateValue"] == "INSUFFICIENT_DATA", f"expected INSUFFICIENT_DATA, got {initial['StateValue']!r}"

    cw.set_alarm_state(
        AlarmName=name,
        StateValue="ALARM",
        StateReason="forced-alarm-for-test",
        StateReasonData=json.dumps({"triggeredBy": "behavioral-check"}),
    )
    alarm = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0],
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=30,
    )
    assert alarm["StateReason"] == "forced-alarm-for-test", f"expected forced-alarm-for-test, got {alarm['StateReason']!r}"

    history = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate", MaxRecords=5)["AlarmHistoryItems"]
    assert history, "expected at least one StateUpdate history item"
    latest = json.loads(history[0]["HistoryData"])
    assert latest["newState"]["stateValue"] == "ALARM", f"expected ALARM, got {latest['newState']['stateValue']!r}"

    # StateReasonData that is not valid JSON is rejected, and the alarm's current state is untouched
    code, message = _client_error(
        lambda: cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="bad-json", StateReasonData="{not-json")
    )
    # Real CloudWatch's wire error code for this validation is "InvalidFormat", not the
    # "InvalidFormatFault" shape name.
    assert code == "InvalidFormat", f"expected InvalidFormat, got {code}"
    expected_message = ""  # AWS returns this refusal with an empty message
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert unchanged["StateValue"] == "ALARM", f"expected ALARM (unchanged), got {unchanged['StateValue']!r}"
    assert unchanged["StateReason"] == "forced-alarm-for-test", (
        f"expected forced-alarm-for-test (unchanged), got {unchanged['StateReason']!r}"
    )

    # a non-existent alarm name is a distinct error boundary
    missing = ctx.unique_name("sim2real-behav-nope-")
    code2, message2 = _client_error(lambda: cw.set_alarm_state(AlarmName=missing, StateValue="OK", StateReason="x"))
    assert code2 == "ResourceNotFound", f"expected ResourceNotFound, got {code2}"
    expected_message2 = ""  # AWS returns this refusal with an empty message
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
