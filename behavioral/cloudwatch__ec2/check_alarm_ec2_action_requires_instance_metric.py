"""alarm-ec2-action-requires-instance-metric."""

from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-ec2-action-requires-instance-metric"

GROUP = "alerting"

SERVICES = ["cloudwatch", "ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ec2:stop alarm action on an AWS/EC2 metric without an InstanceId dimension fails with the
    exact validation error and leaves no alarm, while that metric without actions, and that action
    on an InstanceId metric, are accepted."""
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")
    stop_action = f"arn:aws:automate:{ctx.region}:ec2:stop"

    common: dict[str, Any] = dict(
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="LessThanThreshold",
        ActionsEnabled=True,
    )

    # (1) The rejection under test.
    rejected_name = _xname(ctx, "alarm-nodim")
    ctx.on_cleanup(
        lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[rejected_name])
    )
    try:
        cw.put_metric_alarm(
            AlarmName=rejected_name,
            AlarmActions=[stop_action],
            Tags=_xsvc_tags_kv(),
            **common,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"PutMetricAlarm must reject the EC2 stop action {stop_action} on a metric with no "
            f"InstanceId dimension, but the alarm {rejected_name} was created"
        )
    want = (
        "ValidationError",
        "Invalid use of EC2 action. An EC2 action can only be used if the alarm is monitoring an EC2 "
        "instance.",
    )
    assert (code, message) == want, (
        f"a malformed EC2 alarm action is a client validation failure; expected {want!r}, got "
        f"{(code, message)!r}"
    )

    # The rejected alarm must not have been partially created.
    left_behind = cw.describe_alarms(AlarmNames=[rejected_name])["MetricAlarms"]
    assert not left_behind, (
        f"a rejected PutMetricAlarm must leave no alarm behind, found "
        f"{[a['AlarmName'] for a in left_behind]}"
    )

    # (2) Control A: same metric, action removed -> accepted. Isolates the action as the cause.
    no_action_name = _xname(ctx, "alarm-noaction")
    cw.put_metric_alarm(AlarmName=no_action_name, Tags=_xsvc_tags_kv(), **common)
    ctx.on_cleanup(
        lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[no_action_name])
    )
    described = cw.describe_alarms(AlarmNames=[no_action_name])["MetricAlarms"]
    assert described, (
        f"a dimensionless AWS/EC2 metric alarm with no actions is legal and must be created; "
        f"{no_action_name} is absent"
    )
    assert not described[0].get("AlarmActions"), (
        f"expected no AlarmActions on {no_action_name} since none were specified, got "
        f"{described[0].get('AlarmActions')!r}"
    )

    # (3) Control B: same action, InstanceId dimension added -> accepted. Isolates the dimension.
    # Confirm across the boundary, with EC2 itself, that the id names nothing: the stop action this
    # alarm carries can never affect a real instance even if something fired it.
    instance_id = _PLACEHOLDER_INSTANCE_ID
    try:
        found = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        want = ("InvalidInstanceID.Malformed", f'Invalid id: "{instance_id}"')
        assert (err.get("Code"), err.get("Message")) == want, (
            f"resolving the placeholder instance id {instance_id} raised "
            f"{(err.get('Code'), err.get('Message'))!r}, expected {want!r}"
        )
    else:
        assert not found, (
            f"refusing to point an ec2:stop alarm action at an existing instance: {instance_id} "
            f"resolved to {found!r}"
        )

    dimensioned_name = _xname(ctx, "alarm-dim")
    cw.put_metric_alarm(
        AlarmName=dimensioned_name,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        AlarmActions=[stop_action],
        Tags=_xsvc_tags_kv(),
        **common,
    )
    ctx.on_cleanup(
        lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[dimensioned_name])
    )
    dimensioned = cw.describe_alarms(AlarmNames=[dimensioned_name])["MetricAlarms"]
    assert dimensioned, (
        f"an EC2 stop action IS legal on a per-instance metric; {dimensioned_name} must exist"
    )
    assert dimensioned[0].get("AlarmActions") == [stop_action], (
        f"the ec2:stop pseudo-ARN must round-trip verbatim through DescribeAlarms, got "
        f"{dimensioned[0].get('AlarmActions')!r}"
    )
    dims = {d["Name"]: d["Value"] for d in dimensioned[0].get("Dimensions", [])}
    assert dims == {"InstanceId": instance_id}, (
        f"the InstanceId dimension that made the action legal must round-trip, got {dims!r}"
    )


#: A fixed instance id EC2 refuses as malformed, so every run sends the same request.
_PLACEHOLDER_INSTANCE_ID = "i-feedfacefeedfacef"

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
