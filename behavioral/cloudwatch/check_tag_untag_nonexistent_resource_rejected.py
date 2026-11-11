"""tag-untag-nonexistent-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-nonexistent-resource-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and ListTagsForResource on the ARN of an alarm that never existed
    each fail with ResourceNotFoundException and an empty message; once the alarm exists the same
    tag and untag calls take effect."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-notag-")
    bogus_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{bogus_alarm}"

    # Confirm the alarm really doesn't exist yet (the not-found errors below are
    # the real signal, not a byproduct of some other cause).
    assert cw.describe_alarms(AlarmNames=[bogus_alarm]).get("MetricAlarms", []) == []

    code, message = _err(lambda: cw.tag_resource(ResourceARN=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert code == "ResourceNotFoundException", (
        f"TagResource: expected ResourceNotFoundException for a nonexistent resource ARN, got {code}: {message!r}"
    )
    assert message == "", message

    code, message = _err(lambda: cw.untag_resource(ResourceARN=bogus_arn, TagKeys=["k"]))
    assert code == "ResourceNotFoundException", (
        f"UntagResource: expected ResourceNotFoundException for a nonexistent resource ARN, got {code}: {message!r}"
    )
    assert message == "", message

    code, message = _err(lambda: cw.list_tags_for_resource(ResourceARN=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"ListTagsForResource: expected ResourceNotFoundException for a nonexistent resource ARN, got {code}: {message!r}"
    )
    assert message == "", message

    # Restore leg: create the alarm under the identical name/ARN just probed, and
    # demand the identical Tag/List/Untag/List calls now succeed against it — the
    # positive control that separates "correctly rejects a nonexistent ARN" from
    # "rejects every TagResource/UntagResource/ListTagsForResource call".
    cw.put_metric_alarm(
        AlarmName=bogus_alarm,
        Namespace="Sim2RealBehavioral",
        MetricName="RealMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[bogus_alarm]))

    cw.tag_resource(ResourceARN=bogus_arn, Tags=[{"Key": "k", "Value": "v"}])
    live_tags = cw.list_tags_for_resource(ResourceARN=bogus_arn).get("Tags", [])
    assert live_tags == [{"Key": "k", "Value": "v"}], (
        f"TagResource: expected the tag to stick once the alarm exists, got {live_tags}"
    )

    cw.untag_resource(ResourceARN=bogus_arn, TagKeys=["k"])
    live_tags = cw.list_tags_for_resource(ResourceARN=bogus_arn).get("Tags", [])
    assert live_tags == [], (
        f"UntagResource: expected the tag to be removed once the alarm exists, got {live_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
