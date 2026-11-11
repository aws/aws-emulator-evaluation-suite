"""tag-resource-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-untag-resource-roundtrip"
GROUP = "tagging"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches a tag to a metric alarm's ARN, ListTagsForResource surfaces it,
    and UntagResource removes exactly that tag while leaving others intact."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]

    cw.tag_resource(
        ResourceARN=arn,
        Tags=[{"Key": "sim2real-a", "Value": "one"}, {"Key": "sim2real-b", "Value": "two"}],
    )
    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"sim2real-a": "one", "sim2real-b": "two"}, f"expected exactly the two applied tags, got {tags}"

    cw.untag_resource(ResourceARN=arn, TagKeys=["sim2real-a"])
    tags_after = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags_after == {"sim2real-b": "two"}, f"expected only the untargeted tag to remain, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
