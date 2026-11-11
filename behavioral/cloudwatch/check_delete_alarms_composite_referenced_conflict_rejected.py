"""delete-alarms-composite-referenced-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-alarms-composite-referenced-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a metric alarm referenced only as a composite's ActionsSuppressor fails with
    ValidationError "Cannot delete <name> as there are composite alarm(s) depending on it." and the
    alarm stays; an unreferenced alarm deletes, and all delete once the composite is gone first."""
    cw = ctx.client("cloudwatch")

    rule_alarm = ctx.unique_name("sim2real-composite-rule-")
    suppressor_alarm = ctx.unique_name("sim2real-composite-suppressor-")
    unrelated_alarm = ctx.unique_name("sim2real-composite-unrelated-")
    for name, metric in (
        (rule_alarm, "CompositeRuleMetric"),
        (suppressor_alarm, "CompositeSuppressorMetric"),
        (unrelated_alarm, "CompositeUnrelatedMetric"),
    ):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace="Sim2Real/Behavioral",
            MetricName=metric,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
        )
        ctx.on_cleanup(lambda n=name: _safe(lambda: cw.delete_alarms(AlarmNames=[n])))

    composite_name = ctx.unique_name("sim2real-composite-parent-")
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{rule_alarm}")',
        ActionsSuppressor=suppressor_alarm,
        ActionsSuppressorWaitPeriod=60,
        ActionsSuppressorExtensionPeriod=60,
    )
    ctx.on_cleanup(lambda: _safe(lambda: cw.delete_alarms(AlarmNames=[composite_name])))

    # positive control: an alarm the composite does not reference at all (neither via
    # AlarmRule nor ActionsSuppressor) deletes cleanly while the composite still exists --
    # proving DeleteAlarms is not simply refusing every delete whenever a composite alarm exists.
    cw.delete_alarms(AlarmNames=[unrelated_alarm])
    gone = cw.describe_alarms(AlarmNames=[unrelated_alarm])["MetricAlarms"]
    assert gone == [], f"unrelated, unreferenced alarm should delete cleanly, still present: {gone}"

    # The suppressor alarm is not in the AlarmRule expression at all, yet the composite depends
    # on it via ActionsSuppressor, so deleting it directly must be rejected. CloudWatch answers
    # the generic ValidationError code, not the ResourceConflict shape the DeleteAlarms model
    # documents.
    code, message = _error(lambda: cw.delete_alarms(AlarmNames=[suppressor_alarm]))
    assert code == "ValidationError", f"expected ValidationError deleting the referenced suppressor, got {code}"
    expected_message = f"Cannot delete {suppressor_alarm} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the suppressor alarm must still exist, untouched, after the rejected delete
    still_there = cw.describe_alarms(AlarmNames=[suppressor_alarm])["MetricAlarms"]
    assert len(still_there) == 1 and still_there[0]["AlarmName"] == suppressor_alarm, (
        f"suppressor alarm should still exist after the rejected delete, got {still_there}"
    )

    # tear down the composite first, then both leaf alarms is the permitted path
    cw.delete_alarms(AlarmNames=[composite_name])
    cw.delete_alarms(AlarmNames=[suppressor_alarm])
    cw.delete_alarms(AlarmNames=[rule_alarm])
    remaining = cw.describe_alarms(AlarmNames=[suppressor_alarm, rule_alarm, composite_name])
    assert remaining.get("MetricAlarms", []) == [], f"leaf alarms should be gone, got {remaining.get('MetricAlarms')}"
    assert remaining.get("CompositeAlarms", []) == [], (
        f"composite alarm should be gone, got {remaining.get('CompositeAlarms')}"
    )


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises, so an emulator
    accepting a call AWS refuses is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    """Cleanup: an alarm the check body already deleted (ResourceNotFound) is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
