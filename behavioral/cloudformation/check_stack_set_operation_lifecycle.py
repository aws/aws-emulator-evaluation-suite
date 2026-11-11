"""stack-set-operation-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-operation-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Stack set update operations transition RUNNING->SUCCEEDED and are enumerable via
    operation and operation-result listings."""
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    admin_arn, exec_role_name = _ensure_stackset_roles(ctx)

    ss_name = ctx.unique_name("sim2real-ssop-")
    template_v1 = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack_set(
        StackSetName=ss_name,
        TemplateBody=template_v1,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real", "Value": ss_name}],
    )
    ctx.on_cleanup(lambda: _teardown(cfn, ss_name, account, region))

    create_op = _retry_role_propagation(
        lambda: cfn.create_stack_instances(StackSetName=ss_name, Accounts=[account], Regions=[region])["OperationId"]
    )
    create_status = _wait_operation(cfn, ss_name, create_op)
    assert create_status == "SUCCEEDED", (
        f"create_stack_instances operation {create_op} ended {create_status}: "
        f"{[r.get('StatusReason') for r in cfn.list_stack_set_operation_results(StackSetName=ss_name, OperationId=create_op)['Summaries']]}"
    )

    describe_before = cfn.describe_stack_set(StackSetName=ss_name)["StackSet"]
    assert describe_before["Status"] == "ACTIVE", describe_before["Status"]

    template_v2 = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "sim2real-v2"}}},
        }
    )
    update_op = cfn.update_stack_set(StackSetName=ss_name, TemplateBody=template_v2)["OperationId"]
    update_status = _wait_operation(cfn, ss_name, update_op)
    assert update_status == "SUCCEEDED", update_status

    operations = cfn.list_stack_set_operations(StackSetName=ss_name)["Summaries"]
    op_ids = {o["OperationId"] for o in operations}
    assert {create_op, update_op}.issubset(op_ids), operations

    results = cfn.list_stack_set_operation_results(StackSetName=ss_name, OperationId=update_op)["Summaries"]
    assert results, "expected per-account/region operation results"
    assert all(r["Status"] == "SUCCEEDED" for r in results), results
    assert any(r["Account"] == account and r["Region"] == region for r in results), results

    stack_sets = cfn.list_stack_sets(Status="ACTIVE")["Summaries"]
    assert any(s["StackSetName"] == ss_name for s in stack_sets), stack_sets


def _wait_operation(cfn, ss_name, op_id, timeout_s=420.0, interval_s=10.0):
    def _status():
        return cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]["Status"]

    return _poll_until(_status, lambda s: s in ("SUCCEEDED", "FAILED", "STOPPED"), timeout_s=timeout_s, interval_s=interval_s)


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 5.0):
    """Retry a call that references an IAM role created moments ago in this same run.

    IAM role/trust-policy propagation is eventually consistent: CreateRole's own principal
    validation (MalformedPolicyDocument) and CloudFormation's attempt to assume a brand-new
    role (AccessDenied/ValidationError/InvalidOperationException) can both transiently fail
    until that propagates. Retrying the call itself, rather than sleeping blind before it,
    bounds the wait to only what propagation needs.
    """
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDenied", "ValidationError", "InvalidOperationException", "MalformedPolicyDocument"):
                raise
            time.sleep(delay_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _teardown(cfn, ss_name, account, region) -> None:
    try:
        del_op = cfn.delete_stack_instances(
            StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=False
        )["OperationId"]
        _wait_operation(cfn, ss_name, del_op, timeout_s=300)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise
    try:
        cfn.delete_stack_set(StackSetName=ss_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


def _ensure_stackset_roles(ctx):
    iam = ctx.client("iam")
    admin_role_name = "AWSCloudFormationStackSetAdministrationRole"
    exec_role_name = "AWSCloudFormationStackSetExecutionRole"

    admin_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    try:
        admin_role = iam.get_role(RoleName=admin_role_name)["Role"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust)["Role"]
        iam.put_role_policy(
            RoleName=admin_role_name,
            PolicyName="AssumeStackSetExecRole",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::*:role/{exec_role_name}"}
                    ],
                }
            ),
        )

    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
    )
    try:
        iam.get_role(RoleName=exec_role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        _retry_role_propagation(
            lambda: iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust)
        )
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

    return admin_role["Arn"], exec_role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
