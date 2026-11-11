"""tag-resource-unicode-tag-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-unicode-tag-value-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag values survive TagResource then ListTagsForResource
    unchanged."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="TagRoundTripMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    alarm_arn = described["AlarmArn"]

    tag_value = "métriques-日本語-Ω"
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "purpose", "Value": tag_value}])

    tags_ = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    matches = [t for t in tags_ if t["Key"] == "purpose"]
    assert len(matches) == 1, f"expected exactly one 'purpose' tag, got {tags_!r}"
    assert matches[0]["Value"] == tag_value, (
        f"unicode tag value corrupted: expected {tag_value!r}, got {matches[0]['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
