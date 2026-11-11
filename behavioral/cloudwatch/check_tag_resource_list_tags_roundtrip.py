"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and
    UntagResource removes exactly the requested key without disturbing others."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="TaggedMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    alarm_arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]

    before = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert before == [], f"freshly created alarm should carry no tags yet, got {before}"

    cw.tag_resource(
        ResourceARN=alarm_arn,
        Tags=[{"Key": "team", "Value": "sim2real"}, {"Key": "env", "Value": "behavioral"}],
    )

    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    assert tags == {"team": "sim2real", "env": "behavioral"}, tags

    cw.untag_resource(ResourceARN=alarm_arn, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    assert tags_after == {"team": "sim2real"}, tags_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
