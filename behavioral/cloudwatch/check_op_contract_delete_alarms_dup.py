"""op-contract-deleteAlarms-dup."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteAlarms-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms removes an unreferenced alarm, but for an alarm a composite alarm's AlarmRule
    references it raises ValidationError "Cannot delete <name> as there are composite alarm(s) depending
    on it." and keeps the alarm; once the composite is deleted, the same delete succeeds."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-ns-")
    solo_name = ctx.unique_name("sim2real-behav-cw-alarm-solo-")
    ref_name = ctx.unique_name("sim2real-behav-cw-alarm-ref-")
    composite_name = ctx.unique_name("sim2real-behav-cw-composite-")

    _put_alarm(ctx, solo_name, namespace, "SoloMetric")
    _put_alarm(ctx, ref_name, namespace, "RefMetric")
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{ref_name}")',
        Tags=[{"Key": "sim2real-check", "Value": "delete-alarms-composite-conflict-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_alarms(ctx, [composite_name]))

    # success-path contract: deleting a standalone alarm that nothing references works cleanly.
    cw.delete_alarms(AlarmNames=[solo_name])
    resp = cw.describe_alarms(AlarmNames=[solo_name])
    assert resp["MetricAlarms"] == [], "deleted alarm must no longer be describable"

    # error boundary: deleting the alarm referenced by the composite's AlarmRule is rejected.
    code, message = _error(lambda: cw.delete_alarms(AlarmNames=[ref_name]))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = f"Cannot delete {ref_name} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still_there = cw.describe_alarms(AlarmNames=[ref_name])["MetricAlarms"]
    assert len(still_there) == 1 and still_there[0]["AlarmName"] == ref_name, (
        "referenced alarm must still exist after the rejected delete"
    )

    # positive control: after removing the composite, the same delete now succeeds.
    cw.delete_alarms(AlarmNames=[composite_name])
    cw.delete_alarms(AlarmNames=[ref_name])
    remaining = cw.describe_alarms(AlarmNames=[ref_name])["MetricAlarms"]
    assert remaining == [], f"expected {ref_name!r} gone after the identical delete succeeds, found {remaining!r}"


def _put_alarm(ctx: Any, name: str, namespace: str, metric_name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": "delete-alarms-composite-conflict-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_alarms(ctx, [name]))


def _safe_delete_alarms(ctx: Any, names: list[str]) -> None:
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return the botocore (Code, Message). A SUCCESS raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
