"""cw-delete-alarms-two-composites-rejected-and-nothing-deleted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cw-delete-alarms-two-composites-rejected-and-nothing-deleted"
GROUP = "alarms-rejected"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "concern:metrics", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteAlarms naming two composite alarms plus a metric alarm fails ValidationError and
    deletes nothing in the batch; one composite alone, or with a metric alarm, deletes.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DeleteAlarms.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthDelNs")
    leaf = ctx.unique_name("sim2real-depth-dleaf-")
    free = ctx.unique_name("sim2real-depth-dfree-")
    c1 = ctx.unique_name("sim2real-depth-dc1-")
    c2 = ctx.unique_name("sim2real-depth-dc2-")

    for name in (leaf, free):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName="LeafMetric",
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    for name in (c1, c2):
        cw.put_composite_alarm(
            AlarmName=name,
            AlarmRule=f'ALARM("{leaf}")',
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        # LIFO: both composites are torn down before the leaf they depend on, which is required --
        # CloudWatch refuses to delete an alarm a composite still references.
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    # DescribeAlarms without AlarmTypes returns metric alarms only, so a readback that omits it
    # would report the composites as deleted; that default is asserted before it is relied on.
    default_view = _alarm_names(cw, alarm_types=None)
    assert leaf in default_view, (
        f"the metric alarm {leaf!r} is missing from a default DescribeAlarms; the readback this "
        f"check relies on is broken before the negative is even attempted"
    )
    assert c1 not in default_view and c2 not in default_view, (
        f"DescribeAlarms with no AlarmTypes returned composite alarms {sorted(default_view & {c1, c2})!r}; "
        f"real CloudWatch defaults AlarmTypes to ['MetricAlarm'] and omits composites entirely"
    )

    both_view = _alarm_names(cw, alarm_types=["CompositeAlarm", "MetricAlarm"])
    assert {leaf, free, c1, c2} <= both_view, (
        f"setup incomplete: DescribeAlarms(AlarmTypes=both) is missing "
        f"{sorted({leaf, free, c1, c2} - both_view)!r}"
    )

    # Break exactly one thing: two composite alarms in a single DeleteAlarms. `free` rides along so
    # the atomicity claim covers a batch member that violates no constraint whatsoever.
    error = _error(lambda: cw.delete_alarms(AlarmNames=[c1, c2, free]))
    assert error is not None, (
        f"DeleteAlarms accepted two composite alarms ({c1!r}, {c2!r}) in one request; real "
        f"CloudWatch refuses this, and an acceptance here has already destroyed all three alarms"
    )
    code = error.get("Code")
    message = error.get("Message") or ""
    assert code == "ValidationError", (
        f"the two-composite DeleteAlarms was refused with {code!r}, expected 'ValidationError'; "
        f"message was {message!r}"
    )
    assert message == (
        "Cannot delete [2] Composite Alarms as only one composite alarm delete is allowed in single request"
    ), (
        f"the refusal must name the constraint it enforced, got {message!r}"
    )

    # The effect is absent -- and absent for EVERY member of the batch, including `free`, which
    # violates no constraint at all.
    after = _alarm_names(cw, alarm_types=["CompositeAlarm", "MetricAlarm"])
    assert {leaf, free, c1, c2} <= after, (
        f"the refused DeleteAlarms deleted part of its batch: "
        f"{sorted({leaf, free, c1, c2} - after)!r} are gone. DeleteAlarms must delete nothing when "
        f"it errors, and the metric alarm {free!r} violated no constraint at all"
    )

    # POSITIVE CONTROL 1: one composite alone deletes, so the path was reachable all along and only
    # the two-composite constraint suppressed it.
    cw.delete_alarms(AlarmNames=[c1])
    after_one = _alarm_names(cw, alarm_types=["CompositeAlarm", "MetricAlarm"])
    assert c1 not in after_one, (
        f"positive control failed: deleting the single composite {c1!r} left it in place, so the "
        f"absence asserted above proves nothing about the constraint"
    )
    assert {leaf, free, c2} <= after_one, (
        f"deleting {c1!r} alone also removed {sorted({leaf, free, c2} - after_one)!r}"
    )

    # POSITIVE CONTROL 2: one composite MIXED with an independent metric alarm is accepted, which
    # pins the refusal to the composite COUNT rather than to mixing types in one batch. The metric
    # alarm is not the leaf: dependencies are validated against the pre-request state.
    cw.delete_alarms(AlarmNames=[c2, free])
    after_mixed = _alarm_names(cw, alarm_types=["CompositeAlarm", "MetricAlarm"])
    assert not ({free, c2} & after_mixed), (
        f"positive control failed: a batch of one composite plus one independent metric alarm left "
        f"{sorted({free, c2} & after_mixed)!r} behind, so the refusal above may be about mixing "
        f"types rather than about two composites"
    )
    assert leaf in after_mixed, (
        f"the mixed control batch also removed {leaf!r}, which it never named"
    )


def _alarm_names(cw, *, alarm_types):
    """Every alarm name in the account, paginated; ``alarm_types=None`` uses the service default."""
    kwargs = {} if alarm_types is None else {"AlarmTypes": alarm_types}
    names = set()
    for page in cw.get_paginator("describe_alarms").paginate(**kwargs):
        for alarm in page.get("MetricAlarms", []) + page.get("CompositeAlarms", []):
            names.add(alarm["AlarmName"])
    return names


def _error(fn):
    """Return the botocore Error dict for a ClientError, or None when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
