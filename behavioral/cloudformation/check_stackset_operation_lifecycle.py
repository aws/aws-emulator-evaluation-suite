"""stackset-operation-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-operation-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStackSet's operation is trackable and stoppable through DescribeStackSetOperation,
    ListStackSetOperations, ListStackSetOperationResults and StopStackSetOperation."""
    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    admin_role_arn, exec_role_name = _create_stackset_roles(ctx)

    stackset_name = ctx.unique_name("sim2real-behav-ssop-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps(_topic_template("v1")),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real-behav", "Value": "ssop"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    op0 = _create_stack_instances_with_propagation_retry(ctx, cfn, stackset_name, account_id)
    ctx.on_cleanup(
        lambda: _await_operation(
            cfn,
            stackset_name,
            cfn.delete_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
            )["OperationId"],
        )
    )

    # UpdateStackSet on a SELF_MANAGED StackSet must re-assert the administration role ARN, or
    # AWS rejects it even though CreateStackSet already set one.
    op1 = cfn.update_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps(_topic_template("v2")),
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
    )["OperationId"]

    # op1 was just accepted and has not finished, so stopping it is accepted.
    cfn.stop_stack_set_operation(StackSetName=stackset_name, OperationId=op1)

    final = _poll_until(
        lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=op1)[
            "StackSetOperation"
        ],
        lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=300.0,
        interval_s=8.0,
    )
    assert final["Status"] == "STOPPED", f"StopStackSetOperation accepted but final status is {final['Status']}"

    operations = cfn.list_stack_set_operations(StackSetName=stackset_name)["Summaries"]
    op_ids = {o["OperationId"] for o in operations}
    assert {op0, op1} <= op_ids, f"ListStackSetOperations missing operations: {op_ids}"

    results = cfn.list_stack_set_operation_results(StackSetName=stackset_name, OperationId=op0)["Summaries"]
    assert results, "ListStackSetOperationResults returned no results for a completed operation"
    assert any(r["Account"] == account_id and r["Region"] == ctx.region for r in results)

    # Auto-deployment targets exist only for SERVICE_MANAGED stack sets, so listing them on
    # this SELF_MANAGED one is refused outright.
    code, msg = _client_error(lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=stackset_name))
    assert code == "ValidationError", f"unexpected ListStackSetAutoDeploymentTargets error: {code!r} ({msg!r})"
    expected_msg = "Auto-deployment targets are only available for service-managed stack sets"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _code(exc) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _client_error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_stack_instances_with_propagation_retry(
    ctx, cfn, stackset_name: str, account_id: str, attempts: int = 6, delay_s: float = 15.0
):
    # IAM's create-role-then-assume path is eventually consistent, in two distinct places:
    # CreateStackInstances can reject synchronously with AccessDenied/ValidationError/
    # InvalidOperationException before the roles have propagated at all, and even once that
    # synchronous call is accepted, the operation can still run and fail asynchronously
    # ("<exec role> role with trust relationship to <admin role>" in StatusReason) if the
    # exec role's trust policy hasn't propagated by the time StackSets actually assumes it.
    # Retry both, bounded, rather than sleeping a fixed guess up front.
    last_reason = None
    for attempt in range(attempts):
        op_id = _retry_sync_role_rejection(
            lambda: cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region]
            )["OperationId"]
        )
        status, reasons = _operation_outcome(cfn, stackset_name, op_id)
        if status == "SUCCEEDED":
            return op_id
        last_reason = f"stack set operation {op_id} ended as {status}: {reasons}"
        if not any("trust relationship" in r for r in reasons) or attempt == attempts - 1:
            raise AssertionError(last_reason)
        cleanup_op = cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
        )["OperationId"]
        _await_operation(cfn, stackset_name, cleanup_op)
        time.sleep(delay_s)
    raise AssertionError(f"stack instance creation kept failing on role propagation: {last_reason}")


def _retry_sync_role_rejection(fn, attempts: int = 8, delay_s: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if _code(exc) not in ("AccessDenied", "ValidationError", "InvalidOperationException"):
                raise
            time.sleep(delay_s)
    raise last_exc


def _operation_outcome(cfn, stackset_name: str, operation_id: str, timeout_s: float = 300.0):
    """Poll an operation to a terminal status; return it with the per-instance reasons."""
    result = _poll_until(
        lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=operation_id)[
            "StackSetOperation"
        ],
        lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=timeout_s,
        interval_s=8.0,
    )
    reasons = None
    if result["Status"] != "SUCCEEDED":
        reasons = [
            r.get("StatusReason", "") for r in
            cfn.list_stack_set_operation_results(StackSetName=stackset_name, OperationId=operation_id)["Summaries"]
        ]
    return result["Status"], reasons or []


def _await_operation(cfn, stackset_name: str, operation_id: str, timeout_s: float = 300.0):
    status, reasons = _operation_outcome(cfn, stackset_name, operation_id, timeout_s)
    assert status == "SUCCEEDED", f"stack set operation {operation_id} ended as {status}: {reasons}"


def _retry_malformed_principal(fn, attempts: int = 8, delay_s: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if _code(exc) != "MalformedPolicyDocument":
                raise
            time.sleep(delay_s)
    raise last_exc


def _topic_template(tag_value: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"Tags": [{"Key": "sim2real-behav", "Value": tag_value}]},
            }
        },
    }


def _create_stackset_roles(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    ctx.client("sts")

    admin_role_name = ctx.unique_name("sim2real-ssop-admin-")[:64]
    exec_role_name = ctx.unique_name("sim2real-ssop-exec-")[:64]

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # The admin role must exist before we can reference its ARN as a Principal in the
    # exec role's trust policy -- IAM validates AWS principals against existing entities
    # at CreateRole time, so create the admin role first.
    admin_role_arn = iam.create_role(
        RoleName=admin_role_name,
        AssumeRolePolicyDocument=json.dumps(admin_trust),
        Tags=[{"Key": "sim2real-behav", "Value": "ssop"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_role_name))

    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": admin_role_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    # CreateRole's cross-role principal validation is eventually consistent: a just-created
    # role ARN as Principal can transiently fail with MalformedPolicyDocumentException.
    exec_role_arn = _retry_malformed_principal(
        lambda: iam.create_role(
            RoleName=exec_role_name,
            AssumeRolePolicyDocument=json.dumps(exec_trust),
            Tags=[{"Key": "sim2real-behav", "Value": "ssop"}],
        )["Role"]["Arn"]
    )
    ctx.on_cleanup(lambda: _delete_role(iam, exec_role_name))
    iam.attach_role_policy(
        RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    ctx.on_cleanup(
        lambda: _detach(iam, exec_role_name, "arn:aws:iam::aws:policy/AdministratorAccess")
    )

    # The exec role's Resource field in this policy is just a string, not validated
    # against a Principal, so it can be attached after the exec role is created.
    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_role_arn}],
    }
    iam.put_role_policy(
        RoleName=admin_role_name, PolicyName="assume-exec", PolicyDocument=json.dumps(admin_policy)
    )
    ctx.on_cleanup(lambda: _delete_inline_policy(iam, admin_role_name, "assume-exec"))

    return admin_role_arn, exec_role_name


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _detach(iam, name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_inline_policy(iam, name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
