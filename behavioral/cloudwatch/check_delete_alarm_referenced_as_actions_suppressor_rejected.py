"""delete-alarm-referenced-as-actions-suppressor-rejected."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-alarm-referenced-as-actions-suppressor-rejected"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on an alarm in a composite's AlarmRule and on its ActionsSuppressor fails with
    ValidationError "Cannot delete <name> as there are composite alarm(s) depending on it."; an
    unreferenced alarm deletes, and both delete once the composite is gone."""
    cw = ctx.client("cloudwatch")

    rule_child = ctx.unique_name("sim2real-suppr-rulechild-")
    other_child = ctx.unique_name("sim2real-suppr-otherchild-")
    suppressor = ctx.unique_name("sim2real-suppr-suppressor-")
    unrelated = ctx.unique_name("sim2real-suppr-unrelated-")
    composite = ctx.unique_name("sim2real-suppr-composite-")
    namespace = ctx.unique_name("Sim2Real/ActionsSuppressor")
    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}]

    for name in (rule_child, other_child, suppressor, unrelated):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName="DummyMetric",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
            Tags=resource_tags,
        )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [suppressor]))
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [rule_child, other_child, unrelated]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{rule_child}") OR ALARM("{other_child}")',
        ActionsSuppressor=suppressor,
        ActionsSuppressorExtensionPeriod=60,
        ActionsSuppressorWaitPeriod=60,
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [composite]))

    # (a) exact error when deleting an alarm referenced in the composite's AlarmRule while the
    # composite exists: CloudWatch answers ValidationError (not the ResourceConflict documented
    # for other DeleteAlarms conflicts), naming the still-referenced alarm in the message.
    code, message = _refusal(lambda: cw.delete_alarms(AlarmNames=[rule_child]))
    assert code == "ValidationError", (
        f"expected ValidationError deleting the AlarmRule-referenced alarm, got {code} ({message!r})"
    )
    assert message == (
        f"Cannot delete {rule_child} as there are composite alarm(s) depending on it."
    ), (
        f"unexpected ValidationError message {message!r}"
    )

    # (a2) same exact error code when trying to delete the alarm referenced only as the
    # composite's ActionsSuppressor (not in the AlarmRule) -- the suppressor reference is
    # equally a deletion-blocking dependency.
    code2, message2 = _refusal(lambda: cw.delete_alarms(AlarmNames=[suppressor]))
    assert code2 == "ValidationError", (
        f"expected ValidationError deleting the ActionsSuppressor alarm, got {code2} ({message2!r})"
    )
    assert message2 == (
        f"Cannot delete {suppressor} as there are composite alarm(s) depending on it."
    ), (
        f"unexpected ValidationError message {message2!r}"
    )

    # (b) effect absent: both referenced alarms must still exist afterward
    still_there = cw.describe_alarms(AlarmNames=[rule_child, suppressor])["MetricAlarms"]
    found = {a["AlarmName"] for a in still_there}
    assert found == {rule_child, suppressor}, f"expected both blocked alarms still present, found {found}"

    # (c) positive control: deleting the alarm the composite does not reference at all
    # is NOT blocked and succeeds even while the composite alarm still exists.
    cw.delete_alarms(AlarmNames=[unrelated])
    gone = cw.describe_alarms(AlarmNames=[unrelated])["MetricAlarms"]
    assert gone == [], f"expected unrelated alarm gone after delete, still found {gone}"

    # (d) restore: remove the dependency by deleting the composite, then the identical
    # DeleteAlarms calls that were rejected above must now succeed on both alarms.
    cw.delete_alarms(AlarmNames=[composite])
    cw.delete_alarms(AlarmNames=[rule_child, suppressor])
    restored_gone = cw.describe_alarms(AlarmNames=[rule_child, suppressor])["MetricAlarms"]
    assert restored_gone == [], f"expected both alarms gone once the composite dependency is removed, found {restored_gone}"


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected
    SUCCESS raises, so a target accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _delete_alarms_ignore(cw, names):
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
