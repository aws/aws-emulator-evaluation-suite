"""tag-resource-roundtrip-and-list-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-roundtrip-and-list-tags"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource on an alarm ARN round-trip exactly through ListTagsForResource."""
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    alarm_name = ctx.unique_name("sim2real-cw-tagalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="TaggedMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{alarm_name}"

    before = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert before == [], before

    cw.tag_resource(
        ResourceARN=alarm_arn,
        Tags=[{"Key": "team", "Value": "sim2real"}, {"Key": "env", "Value": "behavioral"}],
    )
    after = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    assert after == {"team": "sim2real", "env": "behavioral"}, after

    cw.untag_resource(ResourceARN=alarm_arn, TagKeys=["team"])
    after_untag = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    assert after_untag == {"env": "behavioral"}, after_untag


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
