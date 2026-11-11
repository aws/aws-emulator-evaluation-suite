"""tag-resource-invalid-key-character-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-character-rejected"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a key holding a character outside the allowed set fails with
    InvalidParameterValue and an empty message and adds no tag, while an ordinary key on the same
    alarm is listed."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="InvalidTagKeyCharTest",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    invalid_key = "bad#key!"

    def _tag_invalid():
        cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": invalid_key, "Value": "x"}])

    code, message = _error_code(_tag_invalid)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}: {message!r}"
    assert message == "", message

    existing = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert not any(t["Key"] == invalid_key for t in existing), (
        f"expected {invalid_key!r} absent from tags, found it in {existing!r}"
    )

    # Positive control: an ordinary tag key on the same alarm succeeds.
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "purpose", "Value": "control"}])
    existing = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert any(t["Key"] == "purpose" and t["Value"] == "control" for t in existing), (
        f"expected purpose=control among tags, got {existing!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
