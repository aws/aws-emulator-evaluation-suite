"""stack-instances-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stack-instances-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances -> DescribeStackInstance/ListStackInstances ->
    UpdateStackInstances -> DeleteStackInstances(RetainStacks) -> the retained
    stack is re-attached via ImportStacksToStackSet, all reflected consistently."""
    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    admin_role_arn, exec_role_name = _create_stackset_roles(ctx)

    template = _topic_template(tag_value="v1")
    stackset_name = ctx.unique_name("sim2real-behav-ss-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps(template),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    _create_stack_instances_with_propagation_retry(cfn, stackset_name, account_id, ctx.region)

    instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert instance["Status"] == "CURRENT", f"unexpected stack instance status: {instance}"
    underlying_stack_id = instance["StackId"]

    summaries = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert any(s["StackId"] == underlying_stack_id for s in summaries), (
        "ListStackInstances missing the created instance"
    )

    op2 = cfn.update_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], ParameterOverrides=[]
    )["OperationId"]
    _await_operation(cfn, stackset_name, op2)
    instance_after_update = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert instance_after_update["Status"] == "CURRENT", (
        f"expected CURRENT after update, got {instance_after_update['Status']}"
    )
    assert instance_after_update["StackId"] == underlying_stack_id, (
        f"update changed the underlying stack id: {instance_after_update['StackId']} != {underlying_stack_id}"
    )

    op3 = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=True
    )["OperationId"]
    _await_operation(cfn, stackset_name, op3)

    empty_summaries = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert not any(s["StackId"] == underlying_stack_id for s in empty_summaries), (
        "instance still listed after DeleteStackInstances"
    )
    not_found, message = _error_code(
        lambda: cfn.describe_stack_instance(
            StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
        )
    )
    assert not_found == "StackInstanceNotFoundException", f"expected not-found, got {not_found}"
    assert message == "StackInstance not found", f"StackInstanceNotFoundException message: {message!r}"

    # the underlying stack survives (RetainStacks=True); re-attach it via import
    op4 = cfn.import_stacks_to_stack_set(
        StackSetName=stackset_name, StackIds=[underlying_stack_id]
    )["OperationId"]
    _await_operation(cfn, stackset_name, op4)

    reimported = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert reimported["Status"] == "CURRENT", f"expected CURRENT after re-import, got {reimported['Status']}"
    assert reimported["StackId"] == underlying_stack_id, (
        f"re-import attached a different stack: {reimported['StackId']} != {underlying_stack_id}"
    )

    # final teardown: remove the instance (and, with RetainStacks=False, its underlying
    # stack) before the stack set itself -- prove both are actually gone rather than
    # trusting the operation's own SUCCEEDED status.
    op5 = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
    )["OperationId"]
    _await_operation(cfn, stackset_name, op5)

    final_not_found, message = _error_code(
        lambda: cfn.describe_stack_instance(
            StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
        )
    )
    assert final_not_found == "StackInstanceNotFoundException", (
        f"expected not-found after final delete, got {final_not_found}"
    )
    assert message == "StackInstance not found", f"StackInstanceNotFoundException message: {message!r}"
    underlying_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=underlying_stack_id)["Stacks"][0]["StackStatus"],
        lambda status: status == "DELETE_COMPLETE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert underlying_status == "DELETE_COMPLETE", (
        f"underlying stack not deleted after RetainStacks=False: {underlying_status}"
    )


def _code(exc) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises, (None, None) on success."""
    try:
        fn()
        return None, None
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 5.0):
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


def _await_operation(cfn, stackset_name: str, operation_id: str, timeout_s: float = 300.0):
    result = _poll_until(
        lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=operation_id)[
            "StackSetOperation"
        ],
        lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=timeout_s,
        interval_s=8.0,
    )
    assert result["Status"] == "SUCCEEDED", f"stack set operation {operation_id} ended as {result['Status']}"
    return result


def _create_stack_instances_with_propagation_retry(
    cfn, stackset_name: str, account_id: str, region: str, attempts: int = 4, delay_s: float = 15.0
) -> None:
    """CreateStackInstances -> await, retried as a whole.

    IAM role propagation can still be incomplete when the async stack-set operation
    actually tries to assume the admin/exec roles, even once the synchronous
    CreateStackInstances call itself has already succeeded -- that lag surfaces as the
    operation ending FAILED, not as an exception on the call, so _retry_role_propagation
    alone does not cover it. Retry the whole create+await, bounded, instead of guessing a
    fixed pre-wait duration; clear the failed instance first so the retry starts clean.
    """
    last_status = None
    for attempt in range(attempts):
        op_id = _retry_role_propagation(
            lambda: cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
            )["OperationId"]
        )
        result = _poll_until(
            lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=op_id)[
                "StackSetOperation"
            ],
            lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=300.0,
            interval_s=8.0,
        )
        if result["Status"] == "SUCCEEDED":
            return
        last_status = result["Status"]
        if attempt < attempts - 1:
            _clear_failed_stack_instance(cfn, stackset_name, account_id, region)
            time.sleep(delay_s)
    raise AssertionError(
        f"create_stack_instances kept failing (last status {last_status}) after {attempts} attempts, "
        "well past the IAM role propagation window"
    )


def _clear_failed_stack_instance(cfn, stackset_name: str, account_id: str, region: str) -> None:
    try:
        del_op = cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[region], RetainStacks=False
        )["OperationId"]
        _poll_until(
            lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=del_op)[
                "StackSetOperation"
            ],
            lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=120.0,
            interval_s=5.0,
        )
    except Exception:  # noqa: BLE001 - best-effort: a failed create may have left nothing to clear
        pass


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

    admin_role_name = ctx.unique_name("sim2real-ss-admin-")[:64]
    exec_role_name = ctx.unique_name("sim2real-ss-exec-")[:64]

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
        Tags=[{"Key": "sim2real-behav", "Value": admin_role_name}],
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
    # Even though the admin role now exists, IAM's cross-role principal validation on
    # CreateRole is itself eventually consistent: referencing a role ARN that was just
    # created (moments ago, in this same run) as a Principal can still transiently
    # fail with MalformedPolicyDocumentException until that propagates. Retry.
    exec_role_arn = _retry_malformed_principal(
        lambda: iam.create_role(
            RoleName=exec_role_name,
            AssumeRolePolicyDocument=json.dumps(exec_trust),
            Tags=[{"Key": "sim2real-behav", "Value": exec_role_name}],
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

    # IAM eventual consistency before StackSets attempts to assume these roles: the first
    # caller (create_stack_instances, below) is wrapped in _retry_role_propagation, which
    # retries AccessDenied/ValidationError/InvalidOperationException with a bounded
    # deadline -- that retry, not a fixed sleep here, is what absorbs the propagation lag.
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
