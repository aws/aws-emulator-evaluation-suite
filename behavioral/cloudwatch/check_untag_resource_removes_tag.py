"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the specified key, leaving other tags intact."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="DummyMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]

    cw.tag_resource(
        ResourceARN=arn,
        Tags=[{"Key": "Team", "Value": "sim2real"}, {"Key": "Env", "Value": "test"}],
    )
    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"Team": "sim2real", "Env": "test"}, f"expected both tags after tag_resource, got {tags}"

    cw.untag_resource(ResourceARN=arn, TagKeys=["Team"])
    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"Env": "test"}, f"expected only 'Env' tag to remain, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
