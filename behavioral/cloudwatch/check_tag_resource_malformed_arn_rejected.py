"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource reject a ResourceARN that is not ARN-shaped with
    InvalidParameterValue naming the value, while a real alarm's ARN is tagged and listed."""
    cw = ctx.client("cloudwatch")
    not_an_arn = ctx.unique_name("sim2real-behav-cwnotanarn-")

    code, message = _error(lambda: cw.tag_resource(ResourceARN=not_an_arn, Tags=[{"Key": "team", "Value": "sim2real"}]))
    expected_message = f"ResourceARN must be valid and belong to a CloudWatch resource: {not_an_arn}"
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    list_code, list_message = _error(lambda: cw.list_tags_for_resource(ResourceARN=not_an_arn))
    assert list_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {list_code}: {list_message!r}"
    )
    assert list_message == expected_message, f"expected message {expected_message!r}, got {list_message!r}"

    # Positive control: a real alarm's own ARN is accepted by both calls.
    alarm_name = ctx.unique_name("sim2real-behav-cwreal-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-behav-cwreal-ns-"),
        MetricName="RealMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))
    real_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{alarm_name}"
    cw.tag_resource(ResourceARN=real_arn, Tags=[{"Key": "team", "Value": "sim2real"}])
    real_tags = cw.list_tags_for_resource(ResourceARN=real_arn)["Tags"]
    assert real_tags == [{"Key": "team", "Value": "sim2real"}], real_tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
