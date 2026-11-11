"""tag-resource-nonexistent-alarm-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-alarm-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an alarm ARN that does not exist is refused, and no tag set is created."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_alarm_name = ctx.unique_name("sim2real-cw-notreal-")
    fake_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{fake_alarm_name}"

    code, message = _error_code(
        lambda: cw.tag_resource(ResourceARN=fake_arn, Tags=[{"Key": "team", "Value": "sim2real"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == "", message

    list_code, list_message = _error_code(lambda: cw.list_tags_for_resource(ResourceARN=fake_arn))
    assert list_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {list_code}: {list_message!r}"
    )
    assert list_message == "", list_message

    # Positive control: tagging a real alarm's ARN succeeds.
    real_alarm = ctx.unique_name("sim2real-cw-real-")
    cw.put_metric_alarm(
        AlarmName=real_alarm,
        Namespace="Sim2RealBehavioral",
        MetricName="RealMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[real_alarm]))
    real_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{real_alarm}"
    cw.tag_resource(ResourceARN=real_arn, Tags=[{"Key": "team", "Value": "sim2real"}])
    tags = cw.list_tags_for_resource(ResourceARN=real_arn)["Tags"]
    assert tags == [{"Key": "team", "Value": "sim2real"}], tags


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
