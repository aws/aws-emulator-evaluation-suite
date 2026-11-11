"""tag-nonexistent-resource-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a well-formed ARN that does not correspond to an existing alarm,
    while the identical call against a real alarm succeeds — the positive control that
    separates "rejects a nonexistent resource" from "TagResource is broken for every ARN"."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{ctx.unique_name('sim2real-cw-nonexistent-')}"

    code, message = _client_error(
        lambda: cw.tag_resource(ResourceARN=fake_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging a nonexistent alarm ARN, got {code}: {message!r}"
    )
    assert message == "", message

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
    cw.tag_resource(ResourceARN=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    real_tags = cw.list_tags_for_resource(ResourceARN=real_arn)["Tags"]
    assert real_tags == [{"Key": "k", "Value": "v"}], (
        f"expected the tag to stick on a real alarm's ARN, got {real_tags}"
    )


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
