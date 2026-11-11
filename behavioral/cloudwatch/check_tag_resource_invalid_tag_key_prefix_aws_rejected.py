"""tag-resource-invalid-tag-key-prefix-aws-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-tag-key-prefix-aws-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key in the reserved "aws:" namespace with
    InvalidParameterValue, and the tag is never applied to the resource. A normal tag
    key succeeds as a positive control on the same alarm.
    """
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    alarm_name = ctx.unique_name("sim2real-tagalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    account_id = sts.get_caller_identity()["Account"]
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{alarm_name}"

    code, message = _error_code(
        lambda: cw.tag_resource(
            ResourceARN=alarm_arn, Tags=[{"Key": "aws:reserved", "Value": "x"}]
        )
    )
    # Empirically (verified against real AWS) a tag key in the reserved "aws:"
    # namespace is denied with the generic "AccessDenied" error (IAM/tag-policy
    # level reserved-namespace protection), rather than a service-level
    # InvalidParameterValue.
    assert code == "AccessDenied", f"expected AccessDenied, got {code}: {message!r}"
    assert message == 'The provided tag keys must not start with any case of "aws:"', message

    # effect absent: the reserved-namespace tag was never applied
    tags_after = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert all(t["Key"] != "aws:reserved" for t in tags_after), (
        f"expected no aws:reserved tag on {alarm_arn}, found {tags_after}"
    )

    # positive control: a normal tag key succeeds
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "Environment", "Value": "sim2real"}])
    tags_after2 = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert {"Key": "Environment", "Value": "sim2real"} in tags_after2, (
        f"expected Environment=sim2real in {tags_after2}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
