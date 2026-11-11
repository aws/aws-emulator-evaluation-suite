"""stackset-operation-monitoring-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-operation-monitoring-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stackset operation's status is trackable end-to-end via
    DescribeStackSetOperation/ListStackSetOperations/ListStackSetOperationResults,
    and is stoppable mid-flight via StopStackSetOperation."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_stackset_roles(ctx)
    account_id = roles["account_id"]
    # Three regions, deployed one at a time, gives us a real window to call Stop
    # before the whole operation finishes.
    regions = ["us-east-1", "us-east-2", "us-west-2"]

    stack_set_name = ctx.unique_name("sim2real-ss-op-")
    cfn.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=json.dumps(_topic_template()),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
        Tags=[{"Key": "sim2real-behav", "Value": "stackset-operation-monitoring-lifecycle"}],
    )
    ctx.on_cleanup(lambda: _cleanup_stackset(ctx, stack_set_name))

    op_id = _retry_role_propagation(
        lambda: cfn.create_stack_instances(
            StackSetName=stack_set_name,
            Accounts=[account_id],
            Regions=regions,
            OperationPreferences={"RegionConcurrencyType": "SEQUENTIAL", "FailureToleranceCount": 3},
        )["OperationId"]
    )

    try:
        cfn.stop_stack_set_operation(StackSetName=stack_set_name, OperationId=op_id)
        stop_requested = True
    except ClientError as exc:
        # The sequential rollout may already have finished before the stop request;
        # no exact message for this refusal is known, so only the code is asserted.
        assert exc.response["Error"]["Code"] == "InvalidOperationException", (
            f"unexpected StopStackSetOperation error: {exc.response['Error']}"
        )
        stop_requested = False

    op = _poll_operation_terminal(cfn, stack_set_name, op_id, timeout_s=420)
    if stop_requested:
        # StopStackSetOperation was accepted, so the operation must actually have
        # stopped -- accepting SUCCEEDED here would let a Stop that silently no-ops
        # (target keeps running to completion) pass anyway.
        assert op["Status"] == "STOPPED", f"StopStackSetOperation accepted but final status is {op['Status']}"
    else:
        assert op["Status"] == "SUCCEEDED", f"stop was rejected as already-terminal, but final status is {op['Status']}"

    op_ids = {o["OperationId"] for o in cfn.list_stack_set_operations(StackSetName=stack_set_name)["Summaries"]}
    assert op_id in op_ids, f"ListStackSetOperations missing {op_id}: {op_ids}"

    results = cfn.list_stack_set_operation_results(StackSetName=stack_set_name, OperationId=op_id)["Summaries"]
    assert len(results) == len(regions), f"expected one result per region ({regions}), got {results}"
    if stop_requested:
        # A region can already have finished (SUCCEEDED) or been halted before/while
        # running (PENDING/CANCELLED); RUNNING can't survive a terminal op and FAILED
        # would mean our own trivial template+roles are broken, so neither is accepted.
        assert all(r["Status"] in ("SUCCEEDED", "CANCELLED", "PENDING") for r in results), results
    else:
        assert all(r["Status"] == "SUCCEEDED" for r in results), results


def _topic_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "StackSetNotFoundException"):
            raise


def _poll_operation_terminal(cfn, stack_set_name: str, operation_id: str, timeout_s=300.0, interval_s=10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    op = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)[
        "StackSetOperation"
    ]
    while op["Status"] in ("RUNNING", "QUEUED", "STOPPING"):
        if time.monotonic() > deadline:
            raise AssertionError(f"stack set operation {operation_id} did not finish within {timeout_s}s: {op}")
        time.sleep(interval_s)
        op = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)[
            "StackSetOperation"
        ]
    return op


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 15.0):
    """CloudFormation assuming a just-created self-managed role is eventually
    consistent; retry the bounded window instead of sleeping blind before the call."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "ValidationError", "InvalidOperationException"):
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _retry_on_malformed_principal(fn, attempts: int = 20, delay_s: float = 15.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _create_self_managed_stackset_roles(ctx) -> dict:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-cfn-exec-")

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    tag = [{"Key": "sim2real-behav", "Value": "stackset-operation-monitoring-lifecycle"}]
    admin_arn = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=tag
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=admin_name)))

    exec_arn = f"arn:aws:iam::{account_id}:role/{exec_name}"
    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}],
    }
    # IAM has a brief eventual-consistency window right after CreateRole during
    # which the new role's ARN isn't yet valid as a Principal in another role's
    # trust policy (MalformedPolicyDocumentException: "Invalid principal in
    # policy"). Retry past that transient window instead of failing.
    _retry_on_malformed_principal(
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust), Tags=tag)
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=exec_name)))

    iam.attach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(
                RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
        )
    )

    iam.put_role_policy(
        RoleName=admin_name,
        PolicyName="AssumeExecRole",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole")))

    # No blind wait here: CreateStackInstances is wrapped in _retry_role_propagation,
    # which retries past CloudFormation's own IAM-assumption eventual-consistency window.
    return {"admin_role_arn": admin_arn, "exec_role_name": exec_name, "account_id": account_id}


def _cleanup_stackset(ctx, stack_set_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        summaries = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise
        return
    accounts = sorted({s["Account"] for s in summaries})
    regions = sorted({s["Region"] for s in summaries})
    if accounts and regions:
        try:
            op_id = cfn.delete_stack_instances(
                StackSetName=stack_set_name, Accounts=accounts, Regions=regions, RetainStacks=False
            )["OperationId"]
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                op = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=op_id)[
                    "StackSetOperation"
                ]
                if op["Status"] not in ("RUNNING", "QUEUED", "STOPPING"):
                    break
                time.sleep(10)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
    _safe(lambda: cfn.delete_stack_set(StackSetName=stack_set_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
