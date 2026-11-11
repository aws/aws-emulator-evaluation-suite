"""tag-resource-empty-string-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-empty-string-value-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag with an empty-string value round-trips exactly through TagResource/ListTagsForResource."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-tag-alarm-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "empty-value-tag", "Value": ""}])

    tags = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    matching = [t for t in tags if t["Key"] == "empty-value-tag"]
    assert matching, f"empty-value-tag was dropped entirely; got tags {tags!r}"
    assert matching[0]["Value"] == "", f"expected empty string value, got {matching[0]['Value']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
