"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "control-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip tags on an alarm
    ARN, and removed tags no longer appear."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="TaggedValue",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]

    cw.tag_resource(ResourceARN=arn, Tags=[{"Key": "sim2real-key", "Value": "sim2real-value"}])
    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"sim2real-key": "sim2real-value"}, f"expected exactly the applied tag, got {tags}"

    cw.untag_resource(ResourceARN=arn, TagKeys=["sim2real-key"])
    tags_after = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags_after == {}, f"expected no tags after UntagResource, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
