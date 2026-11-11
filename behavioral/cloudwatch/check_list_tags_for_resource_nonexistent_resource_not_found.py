"""list-tags-for-resource-nonexistent-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed ARN of a nonexistent alarm raises ResourceNotFoundException
    with an empty message instead of returning an empty tag list, while a real alarm's ARN returns
    exactly the tag set at creation."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    alarm_name = ctx.unique_name("sim2real-behav-ltr-nf-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-behav-ltr-nf-ns-"),
        MetricName="Dummy",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-owner", "Value": "list-tags-nf-probe"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{alarm_name}"

    # positive control: the operation works and returns the tags set at creation
    live_tags = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    assert live_tags == [{"Key": "sim2real-owner", "Value": "list-tags-nf-probe"}], live_tags

    missing_alarm_name = ctx.unique_name("sim2real-behav-no-such-alarm-")
    arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{missing_alarm_name}"

    error = _error(lambda: cw.list_tags_for_resource(ResourceARN=arn))
    assert error == ("ResourceNotFoundException", ""), error


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListTagsForResource to reject a nonexistent ARN, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
