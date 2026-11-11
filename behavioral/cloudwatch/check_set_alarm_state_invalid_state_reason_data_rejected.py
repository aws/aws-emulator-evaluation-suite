"""set-alarm-state-invalid-state-reason-data-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-invalid-state-reason-data-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState must reject StateReasonData that is not syntactically valid
    JSON rather than storing it verbatim or silently coercing it."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="RequestCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    # Positive control: a well-formed call on this same alarm succeeds, so the
    # rejection below can be attributed to the malformed StateReasonData specifically,
    # not to SetAlarmState being unreachable or rejecting every call it receives.
    cw.set_alarm_state(
        AlarmName=name,
        StateValue="OK",
        StateReason="baseline",
        StateReasonData=json.dumps({"note": "sim2real behavioral control"}),
    )
    baseline = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert baseline == "OK", f"positive control did not take effect, state is {baseline}"

    err = _error(
        lambda: cw.set_alarm_state(
            AlarmName=name,
            StateValue="ALARM",
            StateReason="forced",
            StateReasonData="{this is not valid json,,,",
        )
    )
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # The alarm's state must not have been mutated by the rejected call: it must still
    # read back the state the positive control put it in, not merely "not ALARM" (a
    # target that ignores SetAlarmState entirely would pass that weaker check too).
    state = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert state == baseline, (
        f"rejected SetAlarmState call changed state from {baseline} to {state}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected SetAlarmState to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
