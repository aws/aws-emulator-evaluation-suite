"""delete-referenced-child-alarm-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-referenced-child-alarm-rejected"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a child alarm still referenced by a composite alarm's AlarmRule is
    rejected with ValidationError, the child alarm and its history survive untouched, and
    the same delete succeeds once the composite alarm is removed first."""
    cw = ctx.client("cloudwatch")
    child = ctx.unique_name("sim2real-behav-conflictchild-")
    composite = ctx.unique_name("sim2real-behav-conflictcomposite-")

    # A per-run namespace nothing publishes to, and 'ignore', keep the forced state below: no
    # evaluation adds a StateUpdate to the child's history while it is compared.
    cw.put_metric_alarm(
        AlarmName=child,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="CPUUtilization",
        Namespace=ctx.unique_name("Sim2RealConflictChild"),
        Period=60,
        Statistic="Average",
        Threshold=90.0,
        ActionsEnabled=False,
        TreatMissingData="ignore",
    )
    child_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if child_deleted["done"] else cw.delete_alarms(AlarmNames=[child]))

    # Give the child alarm a real StateUpdate history entry to prove it survives untouched.
    cw.set_alarm_state(AlarmName=child, StateValue="ALARM", StateReason="behavioral-conflict-test")

    baseline_history = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        baseline_history = cw.describe_alarm_history(AlarmName=child)["AlarmHistoryItems"]
        if len(baseline_history) >= 2:
            break
        time.sleep(1.0)
    assert len(baseline_history) >= 2, (
        f"expected >=2 alarm history items (create + state update) within 20s, got {len(baseline_history)}"
    )

    cw.put_composite_alarm(AlarmName=composite, AlarmRule=f'ALARM("{child}")', ActionsEnabled=False)
    composite_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None if composite_deleted["done"] else cw.delete_alarms(AlarmNames=[composite])
    )

    # Break exactly one thing: try to delete the child while the composite still references it.
    code, message = _client_error(lambda: cw.delete_alarms(AlarmNames=[child]))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = f"Cannot delete {child} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the child alarm still exists, unchanged history.
    described = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert len(described) == 1 and described[0]["AlarmName"] == child, (
        f"expected exactly [{child!r}] to still exist after the rejected delete, got {described!r}"
    )
    history_after_reject = cw.describe_alarm_history(AlarmName=child)["AlarmHistoryItems"]
    assert len(history_after_reject) == len(baseline_history), (
        "rejected DeleteAlarms must not mutate the child alarm's history: "
        f"expected {len(baseline_history)} items, got {len(history_after_reject)}"
    )

    # Positive control, same file: remove the composite first, then the child deletes cleanly.
    cw.delete_alarms(AlarmNames=[composite])
    composite_deleted["done"] = True

    cw.delete_alarms(AlarmNames=[child])
    child_deleted["done"] = True

    # DescribeAlarms with an unknown name returns an empty list rather than an error; confirm gone.
    remaining = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert remaining == [], f"expected no alarms named {child!r} after delete, got {remaining!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
