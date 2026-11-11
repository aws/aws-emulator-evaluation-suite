"""delete-stackset-with-instances-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stackset-with-instances-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStackSet on a StackSet that still has associated stack instances
    is rejected with StackSetNotEmptyException, not silently accepted."""
    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    admin_role_arn, exec_role_name = _create_stackset_roles(ctx)

    stackset_name = ctx.unique_name("sim2real-behav-ssdel-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    _retry_role_propagation(
        lambda: cfn.create_stack_set(
            StackSetName=stackset_name,
            TemplateBody=json.dumps(template),
            PermissionModel="SELF_MANAGED",
            AdministrationRoleARN=admin_role_arn,
            ExecutionRoleName=exec_role_name,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: cfn.delete_stack_set(StackSetName=stackset_name)))

    _create_stack_instances_with_retry(cfn, stackset_name, account_id, ctx.region)
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: _await_operation(
                cfn,
                stackset_name,
                cfn.delete_stack_instances(
                    StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
                )["OperationId"],
            )
        )
    )

    code, message = _client_error(
        lambda: cfn.delete_stack_set(StackSetName=stackset_name), "DeleteStackSet of a non-empty stack set"
    )
    assert code == "StackSetNotEmptyException", f"expected StackSetNotEmptyException, got {code}"
    assert message == "StackSet is not empty", message

    # effect absent: the rejected delete did not touch the stack set or its instance
    described = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]
    assert described["Status"] == "ACTIVE", f"expected ACTIVE, got {described['Status']!r}"
    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert any(i["Account"] == account_id and i["Region"] == ctx.region for i in instances), (
        f"expected the stack instance to still be listed, got {instances!r}"
    )

    # restore: remove the instances that were the ONLY thing blocking the delete
    remove_op_id = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
    )["OperationId"]
    _await_operation(cfn, stackset_name, remove_op_id)
    remaining = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert remaining == [], f"expected no stack instances after removal, got {remaining!r}"

    # the identical delete_stack_set call rejected above now succeeds once the state that
    # forbade it is gone -- this is what tells "rejects a non-empty stack set" apart from
    # "rejects every delete_stack_set call"
    cfn.delete_stack_set(StackSetName=stackset_name)
    not_found_code, not_found_message = _client_error(
        lambda: cfn.describe_stack_set(StackSetName=stackset_name), "DescribeStackSet of a deleted stack set"
    )
    assert not_found_code == "StackSetNotFoundException", (
        f"expected StackSetNotFoundException after delete, got {not_found_code}"
    )
    assert not_found_message == f"StackSet {stackset_name} not found", not_found_message


def _code(exc) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _unless_gone(fn):
    """Teardown step that is a no-op once the check itself has deleted the stack set."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "StackSetNotFoundException":
            raise


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


def _operation_result(cfn, stackset_name: str, operation_id: str, timeout_s: float = 300.0):
    """Poll the operation to a terminal status and return it; raise on timeout."""
    return _poll_until(
        lambda: cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=operation_id)[
            "StackSetOperation"
        ],
        lambda op: op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=timeout_s,
        interval_s=8.0,
    )


def _operation_failure(cfn, stackset_name: str, operation_id: str, result) -> str:
    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    detail = [(i.get("Status"), i.get("StatusReason"), i.get("StackInstanceStatus")) for i in instances]
    return (
        f"stack set operation {operation_id} ended as {result['Status']}: "
        f"{result.get('StatusReason')!r}; instances={detail!r}"
    )


def _await_operation(cfn, stackset_name: str, operation_id: str, timeout_s: float = 300.0):
    result = _operation_result(cfn, stackset_name, operation_id, timeout_s)
    if result["Status"] != "SUCCEEDED":
        raise AssertionError(_operation_failure(cfn, stackset_name, operation_id, result))
    return result


def _create_stack_instances_with_retry(cfn, stackset_name, account_id, region, timeout_s=180.0, delay_s=10.0):
    """CreateStackSet/CreateStackInstances accept a just-created execution role's ARN
    synchronously, but StackSets' own cross-account trust check is itself eventually
    consistent: the deployment OPERATION can still end FAILED with a per-instance
    StatusReason naming the missing trust relationship well after the roles exist and
    the API calls that created them returned 200. That failure is async, so the
    synchronous AccessDenied/ValidationError retry in _retry_role_propagation never
    sees it -- only re-driving the whole create+await cycle does."""
    deadline = time.monotonic() + timeout_s
    while True:
        op_id = _retry_role_propagation(
            lambda: cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
            )["OperationId"]
        )
        result = _operation_result(cfn, stackset_name, op_id)
        if result["Status"] == "SUCCEEDED":
            return result
        failure = _operation_failure(cfn, stackset_name, op_id, result)
        if "trust relationship" not in failure or time.monotonic() >= deadline:
            raise AssertionError(failure)
        time.sleep(delay_s)


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


def _create_stackset_roles(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    ctx.client("sts")

    admin_role_name = ctx.unique_name("sim2real-ssdel-admin-")[:64]
    exec_role_name = ctx.unique_name("sim2real-ssdel-exec-")[:64]

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
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
