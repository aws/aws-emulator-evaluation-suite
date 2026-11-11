"""put-composite-alarm-parent-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-composite-alarm-parent-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

#: Fixed API limit from the PutCompositeAlarm reference: "Any single alarm can be included in
#: the rule expressions of as many as 150 composite alarms." It is a constant of the API,
#: identical in every account, not a Service Quotas value.
_MAX_PARENTS = 150
_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_ALARM = dict(
    MetricName="ParentLimit",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=1.0,
    ComparisonOperator="GreaterThanThreshold",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One alarm can be a child of at most 150 composite alarms: the 151st PutCompositeAlarm is rejected
    with ValidationError and the exact message naming the child's ARN and stores nothing; after one parent
    is re-pointed elsewhere the same call succeeds, as DescribeAlarms(ParentsOfAlarmName) shows each step."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealParentLimit")
    child = ctx.unique_name("sim2real-parentlim-child-")
    other = ctx.unique_name("sim2real-parentlim-other-")
    for name in (child, other):
        cw.put_metric_alarm(AlarmName=name, Namespace=namespace, Tags=_TAGS, **_ALARM)
        ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))
    child_arn = cw.describe_alarms(AlarmNames=[child], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0][
        "AlarmArn"
    ]
    rule = f'ALARM("{child}")'

    parents = []
    for i in range(_MAX_PARENTS):
        name = ctx.unique_name(f"sim2real-parentlim-p{i:03d}-")
        cw.put_composite_alarm(AlarmName=name, AlarmRule=rule, Tags=_TAGS)
        # DeleteAlarms accepts one composite alarm per request.
        ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))
        parents.append(name)
    listed = _parents_of(cw, child)
    assert listed == sorted(parents), (
        f"DescribeAlarms(ParentsOfAlarmName) must list exactly the {_MAX_PARENTS} composites "
        f"created, got {len(listed)}; missing={sorted(set(parents) - set(listed))[:3]!r} "
        f"extra={sorted(set(listed) - set(parents))[:3]!r}"
    )

    # The 151st parent: refused, nothing stored, the count unchanged.
    extra = ctx.unique_name("sim2real-parentlim-extra-")
    ctx.on_cleanup(lambda: _delete_composite_if_present(cw, extra))
    err = _error(lambda: cw.put_composite_alarm(AlarmName=extra, AlarmRule=rule, Tags=_TAGS))
    assert err["Code"] == "ValidationError", f"expected ValidationError for parent 151, got {err!r}"
    expected = (
        f"Alarm {child_arn} references too many parents. Maximum allowed referenced parent "
        f"count is {_MAX_PARENTS} per alarm."
    )
    assert err["Message"] == expected, f"expected {expected!r}, got {err['Message']!r}"
    absent = cw.describe_alarms(AlarmNames=[extra], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    assert absent == [], f"a refused PutCompositeAlarm must store nothing, got {absent!r}"
    assert _parents_of(cw, child) == sorted(parents), "a refused 151st parent changed the parent set"

    # Restore: re-point one parent at the other child, then the identical call succeeds.
    moved = parents[0]
    cw.put_composite_alarm(AlarmName=moved, AlarmRule=f'ALARM("{other}")')
    cw.put_composite_alarm(AlarmName=extra, AlarmRule=rule, Tags=_TAGS)
    want = sorted([*parents[1:], extra])
    final = _parents_of(cw, child)
    assert final == want, (
        f"after freeing one slot the child's parents must be the remaining 149 plus the new one; "
        f"got {len(final)}, moved-still-listed={moved in final!r}, new-listed={extra in final!r}"
    )
    assert _parents_of(cw, other) == [moved], (
        f"the re-pointed composite must be the other child's only parent, got {_parents_of(cw, other)!r}"
    )


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises: a target that
    accepts what real AWS refuses must fail loudly, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _parents_of(cw, alarm_name) -> list[str]:
    names = []
    paginator = cw.get_paginator("describe_alarms")
    # ParentsOfAlarmName refuses an AlarmTypes filter; parents are composite alarms by definition.
    for page in paginator.paginate(ParentsOfAlarmName=alarm_name):
        assert page["MetricAlarms"] == [], f"a parent must be a composite alarm, got {page['MetricAlarms']!r}"
        names.extend(a["AlarmName"] for a in page["CompositeAlarms"])
    return sorted(names)


def _delete_composite_if_present(cw, name) -> None:
    if cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]:
        cw.delete_alarms(AlarmNames=[name])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
