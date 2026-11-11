"""create-flow-logs-partial-failure."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-flow-logs-partial-failure"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A valid CreateFlowLogs on a VPC returns a FlowLogId with an empty Unsuccessful list, while a
    batch mixing a real VPC with a nonexistent id is rejected whole with InvalidVpcId.NotFound and
    creates no flow log for the valid VPC (no per-item partial delivery).
    """
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    ec2 = ctx.client("ec2")

    role_name = ctx.unique_name("sim2real-behav-flowlogs-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="flow-logs-delivery", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="flow-logs-delivery"))

    log_group_name = ctx.unique_name("/sim2real-behav/flow-logs-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # Reuse an existing VPC rather than creating one; accounts have a VPC-per-region quota.
    vpc_id = _existing_vpc_id(ec2, ctx)

    def _try_create():
        return ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=role_arn,
        )

    # IAM roles are eventually consistent; retry until EC2 can assume the new role.
    resp = _retry_on_client_error(_try_create, timeout_s=90.0, interval_s=5.0)
    assert resp["Unsuccessful"] == [], f"expected no failures, got {resp['Unsuccessful']}"
    flow_log_id = resp["FlowLogIds"][0]
    ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=[flow_log_id]))

    described = ec2.describe_flow_logs(FlowLogIds=[flow_log_id])["FlowLogs"][0]
    assert described["ResourceId"] == vpc_id, (
        f"expected DescribeFlowLogs to report ResourceId {vpc_id!r}, got {described['ResourceId']!r}"
    )
    assert described["LogGroupName"] == log_group_name, (
        f"expected DescribeFlowLogs to report LogGroupName {log_group_name!r}, "
        f"got {described['LogGroupName']!r}"
    )

    # Prefer another existing VPC: an account at its VPC quota would raise VpcLimitExceeded on
    # CreateVpc instead of exercising batch validation.
    vpc_id2 = _second_vpc_id(ec2, ctx, vpc_id)

    existing_flow_log_ids = {
        fl["FlowLogId"]
        for fl in ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id2]}]
        )["FlowLogs"]
    }

    bogus_vpc_id = "vpc-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.create_flow_logs(
            ResourceIds=[vpc_id2, bogus_vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=role_arn,
        )
    )
    assert code == "InvalidVpcId.NotFound", f"expected InvalidVpcId.NotFound, got {code!r}"
    assert message == f"Unknown resource {bogus_vpc_id}", message

    after_flow_log_ids = {
        fl["FlowLogId"]
        for fl in ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id2]}]
        )["FlowLogs"]
    }
    assert after_flow_log_ids == existing_flow_log_ids, (
        "expected no flow log to be created for the valid VPC when the batch "
        "also contains a non-existent VPC id, since CreateFlowLogs rejects "
        "the whole batch instead of partially delivering"
    )


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _existing_vpc_id(ec2, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


def _second_vpc_id(ec2, ctx, primary_vpc_id):
    paginator = ec2.get_paginator("describe_vpcs")
    for page in paginator.paginate():
        for v in page["Vpcs"]:
            if v["VpcId"] != primary_vpc_id:
                return v["VpcId"]
    try:
        vpc_id = ec2.create_vpc(CidrBlock="10.89.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
        return vpc_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "VpcLimitExceeded":
            return primary_vpc_id
        raise


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the batch create_flow_logs call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _retry_on_client_error(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
