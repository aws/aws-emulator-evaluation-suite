"""op-contract-describeFlowLogs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFlowLogs"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFlowLogs reflects a real flow log's configuration and treats a bogus flow log ID as
    a non-matching filter rather than an error."""
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    vpc_id = _get_or_create_vpc(ctx, ec2)

    log_group_name = ctx.unique_name("/sim2real/flowlogs-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": "1"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

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

    # IAM roles are eventually consistent for cross-service assume-role trust; retry briefly.
    flow_log_id = _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name)
    ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=[flow_log_id]))

    # --- success path: the flow log we created is describable with the right configuration ---
    resp = _poll_until(
        lambda: ec2.describe_flow_logs(FlowLogIds=[flow_log_id]),
        lambda r: len(r.get("FlowLogs", [])) == 1,
        timeout_s=30,
        interval_s=2,
    )
    flow_logs = resp["FlowLogs"]
    assert len(flow_logs) == 1, f"expected exactly 1 flow log for {flow_log_id!r}, got {flow_logs!r}"
    fl = flow_logs[0]
    assert fl["FlowLogId"] == flow_log_id, f"expected FlowLogId {flow_log_id!r}, got {fl['FlowLogId']!r}"
    assert fl["ResourceId"] == vpc_id, f"expected ResourceId {vpc_id!r}, got {fl['ResourceId']!r}"
    assert fl["TrafficType"] == "ALL", f"expected TrafficType 'ALL', got {fl['TrafficType']!r}"
    assert fl["LogDestinationType"] == "cloud-watch-logs", (
        f"expected LogDestinationType 'cloud-watch-logs', got {fl['LogDestinationType']!r}"
    )
    assert fl["LogGroupName"] == log_group_name, (
        f"expected LogGroupName {log_group_name!r}, got {fl['LogGroupName']!r}"
    )
    assert fl["FlowLogStatus"] == "ACTIVE", f"expected FlowLogStatus 'ACTIVE', got {fl['FlowLogStatus']!r}"

    # Filtering by resource-id must scope correctly.
    by_resource = ec2.describe_flow_logs(Filter=[{"Name": "resource-id", "Values": [vpc_id]}])
    assert any(f["FlowLogId"] == flow_log_id for f in by_resource["FlowLogs"]), (
        f"expected {flow_log_id!r} among flow logs filtered by resource-id={vpc_id!r}, "
        f"got {[f['FlowLogId'] for f in by_resource['FlowLogs']]!r}"
    )

    # --- boundary: a well-formed but nonexistent flow log ID is treated as an ID filter, not a
    # specific-resource lookup -- real AWS does not raise for this, it simply matches nothing ---
    bogus_id = "fl-0123456789abcdef0"
    empty = ec2.describe_flow_logs(FlowLogIds=[bogus_id])
    assert empty["FlowLogs"] == [], (
        "describing a nonexistent flow log ID should match nothing, not raise or return other flow logs"
    )


def _get_or_create_vpc(ctx, ec2):
    """Create a fresh VPC for the test; if the account is already at its VPC quota
    (a real, observed possibility, not a bug in this check), fall back to reusing an
    existing VPC instead -- flow logs can be attached to any VPC resource."""
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.212.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
        return vpc_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VpcLimitExceeded":
            raise

    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    if not vpcs:
        raise AssertionError("VPC quota exhausted and no existing VPC available to reuse")
    default = [v for v in vpcs if v.get("IsDefault")]
    return (default[0] if default else vpcs[0])["VpcId"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"poll timed out after {timeout_s}s waiting for predicate; last value: {last!r}")


def _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name, timeout_s=60.0, interval_s=3.0):
    """CreateFlowLogs needs the flow-log role's trust to have propagated; retry briefly."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.create_flow_logs(
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
