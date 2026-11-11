"""e2e-composite-alarm-child-deletion-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-composite-alarm-child-deletion-conflict-rejected"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCompositeAlarm naming a missing alarm fails with ValidationError "Could not save the
    composite alarm as alarms [<arn>] ...", then succeeds once it exists; DeleteAlarms on that child
    then fails with "Cannot delete <name> as there are ..." until the composite is deleted."""
    cw = ctx.client("cloudwatch")

    composite = ctx.unique_name("sim2real-cwconf-parent-")
    missing_child = ctx.unique_name("sim2real-cwconf-ghost-")
    namespace = ctx.unique_name("Sim2Real/AlarmConflict-")

    # Break exactly one thing: reference an alarm name that has never been
    # created.
    code, message = _error(
        lambda: cw.put_composite_alarm(AlarmName=composite, AlarmRule=f"ALARM({missing_child})")
    )
    assert code == "ValidationError", f"expected ValidationError referencing a nonexistent alarm, got {code}"
    missing_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{missing_child}"
    assert message == (
        f"Could not save the composite alarm as alarms [{missing_arn}] in the alarm rule do not exist"
    ), f"unexpected PutCompositeAlarm message {message!r}"

    # Effect absent: no composite alarm was created under that name.
    none_created = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ]
    assert none_created == [], f"expected no composite alarm created, found {none_created}"

    # Positive control: create the referenced alarm first, then the
    # identical PutCompositeAlarm call succeeds.
    cw.put_metric_alarm(
        AlarmName=missing_child,
        Namespace=namespace,
        MetricName="Errors",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_alarms(AlarmNames=[missing_child])))

    cw.put_composite_alarm(AlarmName=composite, AlarmRule=f"ALARM({missing_child})")
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_alarms(AlarmNames=[composite])))

    now_created = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ]
    assert len(now_created) == 1, f"expected exactly one composite alarm, got {now_created}"
    assert now_created[0]["AlarmName"] == composite, (
        f"expected composite alarm named {composite}, got {now_created[0]['AlarmName']}"
    )

    # The child deletion conflict: DeleteAlarms on the child while the
    # composite's AlarmRule still references it is rejected.
    conflict_code, conflict_msg = _error(lambda: cw.delete_alarms(AlarmNames=[missing_child]))
    assert conflict_code == "ValidationError", (
        f"expected ValidationError deleting a still-referenced child alarm, got {conflict_code}"
    )
    assert conflict_msg == f"Cannot delete {missing_child} as there are composite alarm(s) depending on it.", f"unexpected DeleteAlarms message {conflict_msg!r}"

    # Effect absent: the child alarm survives the rejected delete.
    still_there = cw.describe_alarms(AlarmNames=[missing_child])["MetricAlarms"]
    assert len(still_there) == 1 and still_there[0]["AlarmName"] == missing_child, (
        f"expected {missing_child} to survive the rejected delete, got {still_there}"
    )

    # Restore: delete the composite first, removing its dependency on the
    # child, then the identical DeleteAlarms call on the child now succeeds.
    cw.delete_alarms(AlarmNames=[composite])
    cw.delete_alarms(AlarmNames=[missing_child])
    gone = cw.describe_alarms(AlarmNames=[composite, missing_child])
    assert gone["MetricAlarms"] == [], f"expected no metric alarms left, got {gone['MetricAlarms']}"
    assert gone["CompositeAlarms"] == [], f"expected no composite alarms left, got {gone['CompositeAlarms']}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so an over-permissive target's acceptance is never reported as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
