"""op-contract-list-tags-for-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-tags-for-resource"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns tags set at alarm creation, and 404s for a non-existent alarm ARN."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-ltr-ns-")
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{alarm_name}"

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ns,
        MetricName="Dummy",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "team", "Value": "observability"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    tags = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert {"Key": "team", "Value": "observability"} in tags, f"expected team=observability tag, got {tags}"

    missing_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{ctx.unique_name('sim2real-behav-nope-')}"
    code, message = _error(lambda: cw.list_tags_for_resource(ResourceARN=missing_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # real AWS sends this refusal with an empty message
    assert message == "", f"expected an empty refusal message, got {message!r}"

    # Cleanup already deletes this alarm; prove the delete here so it's asserted, not just
    # a teardown side effect — a deleted alarm must be gone and unusable, not merely absent.
    cw.delete_alarms(AlarmNames=[alarm_name])

    code, message = _error(lambda: cw.list_tags_for_resource(ResourceARN=alarm_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    assert message == "", f"expected an empty refusal message after delete, got {message!r}"

    code, message = _error(
        lambda: cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "team", "Value": "observability"}])
    )
    assert code == "ResourceNotFoundException", f"expected TagResource on a deleted alarm to fail, got {code}"
    assert message == "", f"expected an empty TagResource refusal message, got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
