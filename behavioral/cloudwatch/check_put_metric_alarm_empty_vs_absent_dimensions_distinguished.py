"""put-metric-alarm-empty-vs-absent-dimensions-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-metric-alarm-empty-vs-absent-dimensions-distinguished"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarms reports an alarm put with Dimensions=[] and one put without Dimensions identically
    (the Dimensions key present on both or neither, and empty on both): over the Query protocol an empty
    list and an omitted one serialize to the same request."""
    cw = ctx.client("cloudwatch")
    name_empty = ctx.unique_name("sim2real-behav-cw-alarm-emptydims-")
    name_absent = ctx.unique_name("sim2real-behav-cw-alarm-absentdims-")
    namespace = ctx.unique_name("sim2real-behav-cw-alarmns-")
    common = dict(
        Namespace=namespace,
        MetricName="FakeMetricForDimTest",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )

    cw.put_metric_alarm(AlarmName=name_empty, Dimensions=[], **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name_empty]))
    cw.put_metric_alarm(AlarmName=name_absent, **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name_absent]))

    described = cw.describe_alarms(AlarmNames=[name_empty, name_absent])["MetricAlarms"]
    by_name = {a["AlarmName"]: a for a in described}
    assert set(by_name) == {name_empty, name_absent}, by_name.keys()

    alarm_empty = by_name[name_empty]
    alarm_absent = by_name[name_absent]

    # Compare key presence before defaulting with .get(..., []): emitting the Dimensions key
    # for one alarm but not the other is a difference the defaulted lists would hide.
    has_dims_empty = "Dimensions" in alarm_empty
    has_dims_absent = "Dimensions" in alarm_absent
    assert has_dims_empty == has_dims_absent, (has_dims_empty, has_dims_absent)

    dims_empty = alarm_empty.get("Dimensions", [])
    dims_absent = alarm_absent.get("Dimensions", [])
    assert dims_empty == [], dims_empty
    assert dims_absent == [], dims_absent
    assert dims_empty == dims_absent, (dims_empty, dims_absent)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

