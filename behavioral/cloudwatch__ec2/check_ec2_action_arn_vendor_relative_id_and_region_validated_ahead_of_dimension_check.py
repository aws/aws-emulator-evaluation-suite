"""ec2-action-arn-vendor-relative-id-and-region-validated-ahead-of-dimension-check."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-action-arn-vendor-relative-id-and-region-validated-ahead-of-dimension-check"
GROUP = "representation"
SERVICES = ["cloudwatch", "ec2"]

#: EC2 refuses this id as malformed, so it never resolves to a real instance.
_PLACEHOLDER_INSTANCE_ID = "i-feedfacefeedfacef"

_COMMON_ALARM_KWARGS: dict[str, Any] = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=300,
    EvaluationPeriods=1,
    Threshold=10.0,
    ComparisonOperator="LessThanThreshold",
)


def _reject(fn):
    """The (Code, Message) of the ClientError ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A malformed EC2 alarm-action ARN -- an unknown relative id for its vendor, or a region other
    than the alarm's own -- is rejected with its exact message, on a metric that already carries an
    InstanceId dimension; the well-formed SWF-form action is accepted and round-trips verbatim.
    """
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")

    # The dimension that makes an EC2 action legal is a placeholder: no real instance is touched,
    # and EC2 itself refuses to resolve the id, which the check confirms across the boundary.
    try:
        found = ec2.describe_instances(InstanceIds=[_PLACEHOLDER_INSTANCE_ID])["Reservations"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        want = ("InvalidInstanceID.Malformed", f'Invalid id: "{_PLACEHOLDER_INSTANCE_ID}"')
        assert (err.get("Code"), err.get("Message")) == want, (
            f"resolving the placeholder instance id raised {(err.get('Code'), err.get('Message'))!r}, "
            f"expected {want!r}"
        )
    else:
        raise AssertionError(
            f"the placeholder instance id must name nothing real, but DescribeInstances returned "
            f"{found!r}"
        )

    dims = [{"Name": "InstanceId", "Value": _PLACEHOLDER_INSTANCE_ID}]

    # ---- positive control: the SWF-form action, never exercised elsewhere, is accepted ---------- #
    swf_stop = f"arn:aws:swf:{ctx.region}:{ctx.account}:action/actions/AWS_EC2.InstanceId.Stop/1.0"
    accepted_name = _xname(ctx, "alarm-swf-ok")
    cw.put_metric_alarm(
        AlarmName=accepted_name, Dimensions=dims, AlarmActions=[swf_stop],
        Tags=_xsvc_tags_kv(), **_COMMON_ALARM_KWARGS,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[accepted_name]))
    described = cw.describe_alarms(AlarmNames=[accepted_name])["MetricAlarms"]
    assert described, f"a well-formed SWF-form EC2 action must be accepted; {accepted_name} is absent"
    assert described[0].get("AlarmActions") == [swf_stop], (
        f"the SWF-form pseudo-ARN must round-trip verbatim through DescribeAlarms, got "
        f"{described[0].get('AlarmActions')!r}"
    )

    # ---- negative: an unknown relative id for the swf vendor, same dimensioned metric ------------ #
    swf_bad = f"arn:aws:swf:{ctx.region}:{ctx.account}:action/actions/AWS_EC2.InstanceId.Pause/1.0"
    swf_bad_name = _xname(ctx, "alarm-swf-bad")
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[swf_bad_name]))
    got = _reject(lambda: cw.put_metric_alarm(
        AlarmName=swf_bad_name, Dimensions=dims, AlarmActions=[swf_bad],
        Tags=_xsvc_tags_kv(), **_COMMON_ALARM_KWARGS,
    ))
    want = (
        "ValidationError",
        'The vendor "swf" can not be used with relative id '
        "action/actions/AWS_EC2.InstanceId.Pause/1.0. Allowed relative IDs are "
        "action/actions/AWS_EC2.InstanceId.Stop/1.0, action/actions/AWS_EC2.InstanceId.Terminate/1.0, "
        "action/actions/AWS_EC2.InstanceId.Recover/1.0, action/actions/AWS_EC2.InstanceId.Reboot/1.0",
    )
    assert got == want, f"expected {want!r} for an unknown swf relative id, got {got!r}"
    left = cw.describe_alarms(AlarmNames=[swf_bad_name])["MetricAlarms"]
    assert not left, f"a rejected PutMetricAlarm must leave no alarm behind, found {left!r}"

    # ---- negative: an unknown relative id for the automate vendor, same dimensioned metric ------- #
    automate_bad = f"arn:aws:automate:{ctx.region}:ec2:pause"
    automate_bad_name = _xname(ctx, "alarm-auto-bad")
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[automate_bad_name]))
    got = _reject(lambda: cw.put_metric_alarm(
        AlarmName=automate_bad_name, Dimensions=dims, AlarmActions=[automate_bad],
        Tags=_xsvc_tags_kv(), **_COMMON_ALARM_KWARGS,
    ))
    want = (
        "ValidationError",
        'The vendor "automate" cannot be used with relative id pause. Allowed relative IDs are '
        "ec2:stop, ec2:terminate, ec2:recover, ec2:reboot",
    )
    assert got == want, f"expected {want!r} for an unknown automate relative id, got {got!r}"
    left = cw.describe_alarms(AlarmNames=[automate_bad_name])["MetricAlarms"]
    assert not left, f"a rejected PutMetricAlarm must leave no alarm behind, found {left!r}"

    # ---- negative: a well-formed action naming a region other than the alarm's own --------------- #
    # us-east-1 deliberately differs from ctx.region: the action ARN's own region segment is the
    # subject under test, and the alarm's actual region must be the one AWS reports back.
    foreign_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    wrong_region_action = f"arn:aws:automate:{foreign_region}:ec2:stop"
    wrong_region_name = _xname(ctx, "alarm-auto-region")
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[wrong_region_name]))
    got = _reject(lambda: cw.put_metric_alarm(
        AlarmName=wrong_region_name, Dimensions=dims, AlarmActions=[wrong_region_action],
        Tags=_xsvc_tags_kv(), **_COMMON_ALARM_KWARGS,
    ))
    want = (
        "ValidationError",
        f"Invalid region {foreign_region} specified. Only {ctx.region} is supported.",
    )
    assert got == want, f"expected {want!r} for an action naming a foreign region, got {got!r}"
    left = cw.describe_alarms(AlarmNames=[wrong_region_name])["MetricAlarms"]
    assert not left, f"a rejected PutMetricAlarm must leave no alarm behind, found {left!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
