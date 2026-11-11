"""e2e-stackset-drift-detect-then-remediate."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "e2e-stackset-drift-detect-then-remediate"
GROUP = "e2e"
SERVICES = ["cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: template-value
"""

_REMEDIATED_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: remediated-value
"""



@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A stack instance whose SNS topic is changed outside CloudFormation is detected as DRIFTED;
    an UpdateStackSet with a new DisplayName overwrites the topic and the instance reads IN_SYNC."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    sns = ctx.client("sns")
    account_id = sts.get_caller_identity()["Account"]

    admin_role_name, exec_role_name = _create_self_managed_roles(ctx)

    stackset_name = ctx.unique_name("sim2real-behav-ss-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=f"arn:aws:iam::{account_id}:role/{admin_role_name}",
        ExecutionRoleName=exec_role_name,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    op_status = _create_instance_with_retry(ctx, stackset_name, account_id)
    assert op_status == "SUCCEEDED", f"CreateStackInstances ended in {op_status}"
    ctx.on_cleanup(
        lambda: _wait_stackset_operation(
            ctx,
            stackset_name,
            cfn.delete_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
            )["OperationId"],
            timeout_s=300,
        )
    )

    instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    instance_stack_id = instance["StackId"]

    resources = cfn.describe_stack_resources(StackName=instance_stack_id)["StackResources"]
    topic_arn = next(r for r in resources if r["LogicalResourceId"] == "Topic")["PhysicalResourceId"]

    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="DisplayName", AttributeValue="drifted-value")

    drift_op_1 = cfn.detect_stack_set_drift(StackSetName=stackset_name)["OperationId"]
    drift_status_1 = _wait_stackset_operation(ctx, stackset_name, drift_op_1, timeout_s=300)
    assert drift_status_1 == "SUCCEEDED", f"first drift detection ended in {drift_status_1}"

    drifted_instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert drifted_instance["DriftStatus"] == "DRIFTED", f"expected DRIFTED, got {drifted_instance['DriftStatus']}"

    update_op = cfn.update_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_REMEDIATED_TEMPLATE,
        AdministrationRoleARN=f"arn:aws:iam::{account_id}:role/{admin_role_name}",
        ExecutionRoleName=exec_role_name,
    )["OperationId"]
    update_status = _wait_stackset_operation(ctx, stackset_name, update_op, timeout_s=300)
    assert update_status == "SUCCEEDED", f"remediation UpdateStackSet ended in {update_status}"

    remediated_topic = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert remediated_topic.get("DisplayName") == "remediated-value", (
        f"expected remediated-value, got {remediated_topic.get('DisplayName')}"
    )

    drift_op_2 = cfn.detect_stack_set_drift(StackSetName=stackset_name)["OperationId"]
    drift_status_2 = _wait_stackset_operation(ctx, stackset_name, drift_op_2, timeout_s=300)
    assert drift_status_2 == "SUCCEEDED", f"second drift detection ended in {drift_status_2}"

    remediated_instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert remediated_instance["DriftStatus"] == "IN_SYNC", f"expected IN_SYNC, got {remediated_instance['DriftStatus']}"


def _wait_stackset_operation(ctx, stackset_name: str, operation_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=operation_id)[
            "StackSetOperation"
        ]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack-set operation {operation_id} did not finish within {timeout_s}s (last={status})")


def _create_instance_with_retry(ctx, stackset_name: str, account_id: str, timeout_s: float = 300.0) -> str:
    """CreateStackInstances asynchronously assumes the just-created execution role; retry a
    non-SUCCEEDED operation to a deadline to absorb IAM propagation delay."""
    cfn = ctx.client("cloudformation")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        op_id = cfn.create_stack_instances(StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region])[
            "OperationId"
        ]
        status = _wait_stackset_operation(ctx, stackset_name, op_id, timeout_s=timeout_s)
        if status == "SUCCEEDED" or time.monotonic() >= deadline:
            return status
        time.sleep(2)


def _create_role_with_retry(iam, role_name: str, trust_policy: dict, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM principals referenced in a fresh role's trust policy can lag briefly behind
    creation; retry MalformedPolicyDocument to absorb that propagation delay."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_self_managed_roles(ctx):

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    admin_role_name = ctx.unique_name("sim2real-cfnadmin-")
    exec_role_name = ctx.unique_name("sim2real-cfnexec-")

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    admin_role_arn = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=json.dumps(admin_trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_role_name))

    iam.put_role_policy(
        RoleName=admin_role_name,
        PolicyName="AssumeExecutionRole",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": f"arn:aws:iam::{account_id}:role/{exec_role_name}",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_role_name, PolicyName="AssumeExecutionRole"))

    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role_arn}, "Action": "sts:AssumeRole"}],
    }
    _create_role_with_retry(iam, exec_role_name, exec_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))

    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )

    return admin_role_name, exec_role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
