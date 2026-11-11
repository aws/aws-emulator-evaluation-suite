"""stack-set-drift-detection-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-drift-detection-lifecycle"
GROUP = 'drift'
SERVICES = ['cloudformation']

_TAGS = [{"Key": "sim2real", "Value": "stack-set-drift-detection-lifecycle"}]

_TEMPLATE = json.dumps({
    "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "sim2real-baseline"}}},
})


def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=300, interval_s=3):
    """Poll DescribeStackSetOperation until Status is in targets; return the operation dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]
        if op.get("Status") in target:
            return op
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not reach {target} (last={op.get('Status') if op else None!r})")

def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0, interval_s=5.0):
    """A trust policy naming a role created moments ago can lag briefly behind creation;
    retry MalformedPolicyDocument to absorb that IAM propagation delay."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _create_stack_set_with_retry(cf, name, admin_arn, exec_name, timeout_s=90.0, interval_s=5.0):
    """CreateStackSet can reject a just-created administration role until IAM propagates it;
    retry the call itself rather than sleeping a guessed amount first."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cf.create_stack_set(
                StackSetName=name,
                TemplateBody=_TEMPLATE,
                PermissionModel="SELF_MANAGED",
                AdministrationRoleARN=admin_arn,
                ExecutionRoleName=exec_name,
                Tags=_TAGS,
            )
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateStackSet never succeeded (role propagation?): {last_err}")

def _create_instances_with_retry(cf, name, account, region, timeout_s=240.0, interval_s=15.0):
    """CFN assumes the execution role asynchronously after CreateStackInstances returns, so a
    role-propagation race shows up as a FAILED operation; retry the whole create-and-wait cycle."""
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op_id = cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region])["OperationId"]
        op = _wait_stack_set_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
        if op["Status"] == "SUCCEEDED":
            return op_id
        time.sleep(interval_s)
    raise AssertionError(f"CreateStackInstances never reached SUCCEEDED (role propagation?): {op}")

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec self-managed StackSet role pair; return (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    _create_role_with_retry(iam, exec_name, exec_trust)
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    return admin["Role"]["Arn"], exec_name

def _teardown_stack_set(cf, name):
    """Delete any instances (wait for the op), then delete the stack set."""
    try:
        summaries = cf.list_stack_instances(StackSetName=name).get("Summaries", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if summaries:
        accounts = sorted({s["Account"] for s in summaries})
        regions = sorted({s["Region"] for s in summaries})
        try:
            op = cf.delete_stack_instances(
                StackSetName=name, Accounts=accounts, Regions=regions, RetainStacks=False
            )
            _wait_stack_set_operation(cf, name, op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DetectStackSetDrift, read via ListStackInstanceResourceDrifts, reports the topic IN_SYNC,
    then MODIFIED with a /DisplayName difference after the topic is changed directly."""
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    name = ctx.unique_name("sim2real-behav-ssdrift-")
    _create_stack_set_with_retry(cf, name, admin_arn, exec_name)
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    _create_instances_with_retry(cf, name, account, region)

    stack_id = cf.describe_stack_instance(
        StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=region
    )["StackInstance"]["StackId"]
    topic_arn = next(
        r["PhysicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack_id)["StackResources"]
        if r["LogicalResourceId"] == "Topic"
    )

    def _detect_and_read_topic_drift():
        drift_op_id = cf.detect_stack_set_drift(StackSetName=name)["OperationId"]
        result = _wait_stack_set_operation(cf, name, drift_op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
        assert result["Status"] == "SUCCEEDED", f"drift-detection operation ended as {result['Status']!r}: {result}"
        summaries = cf.list_stack_instance_resource_drifts(
            StackSetName=name,
            StackInstanceAccount=account,
            StackInstanceRegion=region,
            OperationId=drift_op_id,
        )["Summaries"]
        by_logical_id = {s["LogicalResourceId"]: s for s in summaries}
        assert "Topic" in by_logical_id, f"no per-resource drift summary for Topic: {by_logical_id}"
        return by_logical_id["Topic"]

    baseline = _detect_and_read_topic_drift()
    assert baseline["StackResourceDriftStatus"] == "IN_SYNC", f"expected IN_SYNC before any out-of-band change: {baseline}"

    # drift the topic directly, bypassing CloudFormation entirely
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="DisplayName", AttributeValue="sim2real-drifted")

    drifted = _detect_and_read_topic_drift()
    assert drifted["StackResourceDriftStatus"] == "MODIFIED", f"expected MODIFIED after the out-of-band change: {drifted}"
    diffs = {d["PropertyPath"]: d for d in drifted.get("PropertyDifferences", [])}
    assert "/DisplayName" in diffs, f"expected a /DisplayName property difference: {drifted.get('PropertyDifferences')}"
    assert diffs["/DisplayName"]["ActualValue"] == "sim2real-drifted", diffs["/DisplayName"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
