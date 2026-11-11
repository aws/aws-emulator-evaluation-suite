"""flow-log-custom-format-vs-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-log-custom-format-vs-default"
GROUP = "flow-logs"
SERVICES = ["ec2"]

_CUSTOM_FORMAT = "${version} ${srcaddr} ${dstaddr} ${action}"
_DEFAULT_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} "
    "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFlowLogs reports the exact custom LogFormat a flow log was created with.

    One created with no LogFormat reports the documented default format string, not an empty field.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
    """
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    vpc_id = _get_or_create_vpc(ctx, ec2)
    role_arn = _create_flow_log_role(ctx, iam)

    log_group_with_format = ctx.unique_name("/sim2real/flowlogs-fmt-")
    logs.create_log_group(logGroupName=log_group_with_format, tags={"sim2real": "1"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_with_format))

    log_group_default = ctx.unique_name("/sim2real/flowlogs-def-")
    logs.create_log_group(logGroupName=log_group_default, tags={"sim2real": "1"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_default))

    with_format_id = _retry_create_flow_log(
        ec2, vpc_id, role_arn, log_group_with_format, log_format=_CUSTOM_FORMAT
    )
    ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=[with_format_id]))

    without_format_id = _retry_create_flow_log(
        ec2, vpc_id, role_arn, log_group_default, log_format=None
    )
    ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=[without_format_id]))

    described = _poll_until(
        lambda: {
            fl["FlowLogId"]: fl
            for fl in ec2.describe_flow_logs(
                FlowLogIds=[with_format_id, without_format_id]
            )["FlowLogs"]
        },
        lambda d: len(d) == 2,
        timeout_s=30,
        interval_s=2,
    )

    with_format = described[with_format_id]
    assert with_format["LogFormat"] == _CUSTOM_FORMAT, (
        f"expected LogFormat {_CUSTOM_FORMAT!r} for the explicitly-formatted flow log, "
        f"got {with_format.get('LogFormat')!r}"
    )

    without_format = described[without_format_id]
    assert without_format["LogFormat"] == _DEFAULT_FORMAT, (
        f"expected the documented default LogFormat {_DEFAULT_FORMAT!r} for a flow log created "
        f"with no LogFormat, got {without_format.get('LogFormat')!r}"
    )

    assert with_format["LogFormat"] != without_format["LogFormat"], (
        "the custom-format and default-format flow logs reported identical LogFormat values; "
        "the two creates had no observable difference"
    )


def _get_or_create_vpc(ctx, ec2):
    """A VPC this check owns; a pre-existing VPC is never adopted (account-independent)."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.213.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_flow_log_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-flowlogs-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"poll timed out after {timeout_s}s waiting for predicate; last value: {last!r}")


def _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name, *, log_format, timeout_s=60.0, interval_s=3.0):
    """CreateFlowLogs needs the flow-log role's trust to have propagated; retry briefly."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    kwargs = dict(
        ResourceType="VPC",
        ResourceIds=[vpc_id],
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn=role_arn,
        TagSpecifications=[
            {"ResourceType": "vpc-flow-log", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )
    if log_format is not None:
        kwargs["LogFormat"] = log_format
    while time.monotonic() < deadline:
        try:
            resp = ec2.create_flow_logs(**kwargs)
            if resp.get("Unsuccessful"):
                last_error = resp["Unsuccessful"][0]["Error"]["Message"]
                time.sleep(interval_s)
                continue
            return resp["FlowLogIds"][0]
        except ClientError as exc:
            last_error = str(exc)
            time.sleep(interval_s)
    raise AssertionError(f"CreateFlowLogs never succeeded (IAM propagation?): {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
