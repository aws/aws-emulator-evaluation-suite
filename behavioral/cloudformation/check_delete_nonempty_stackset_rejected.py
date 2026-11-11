"""delete-nonempty-stackset-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonempty-stackset-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStackSet with an instance still present fails with StackSetNotEmptyException "StackSet is not
    empty" and leaves the stack set ACTIVE with its instance; once the instance is removed the same delete
    succeeds and DescribeStackSet reports "StackSet <name> not found"."""
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    admin_arn, exec_role_name = _ensure_stackset_roles(ctx)

    ss_name = ctx.unique_name("sim2real-ssnonempty-")
    template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack_set(
        StackSetName=ss_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real", "Value": "delete-nonempty-stackset-rejected"}],
    )
    ctx.on_cleanup(lambda: _teardown(cfn, ss_name, account, region))

    create_op = _create_stack_instances_with_retry(cfn, ss_name, account, region)
    status = _wait_operation(cfn, ss_name, create_op)
    assert status == "SUCCEEDED", f"{status}: {_operation_failure_reason(cfn, ss_name, create_op)}"

    got = _expect_error(lambda: cfn.delete_stack_set(StackSetName=ss_name))
    expected = ("StackSetNotEmptyException", "StackSet is not empty")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # effect-absent: the rejected delete must not have touched the stack set or its instance.
    described = cfn.describe_stack_set(StackSetName=ss_name)["StackSet"]
    assert described["Status"] == "ACTIVE", f"stack set should still be ACTIVE, got {described['Status']}"
    instances = cfn.list_stack_instances(StackSetName=ss_name)["Summaries"]
    assert any(i["Account"] == account and i["Region"] == region for i in instances), (
        f"stack instance should still exist after the rejected delete, saw {instances}"
    )

    # restore: once the blocking instance is gone, the identical delete call succeeds --
    # this is what distinguishes "rejects a nonempty stack set" from "rejects every delete".
    del_op = cfn.delete_stack_instances(
        StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=False
    )["OperationId"]
    del_status = _wait_operation(cfn, ss_name, del_op)
    assert del_status == "SUCCEEDED", del_status

    cfn.delete_stack_set(StackSetName=ss_name)
    gone = _expect_error(lambda: cfn.describe_stack_set(StackSetName=ss_name))
    expected_gone = ("StackSetNotFoundException", f"StackSet {ss_name} not found")
    assert gone == expected_gone, f"expected the stack set gone {expected_gone!r}, got {gone!r}"


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_operation(cfn, ss_name, op_id, timeout_s=420.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack set operation {op_id} did not finish, last={status}")
        time.sleep(interval_s)


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


def _operation_failure_reason(cfn, ss_name, op_id):
    try:
        results = cfn.list_stack_set_operation_results(StackSetName=ss_name, OperationId=op_id)["Summaries"]
        return [(r.get("Status"), r.get("StatusReason")) for r in results]
    except ClientError as exc:
        return f"<could not fetch results: {exc}>"


def _start_create_stack_instances(cfn, ss_name, account, region, deadline, interval_s):
    """CreateStackInstances can transiently reject a just-created SELF_MANAGED admin/exec
    role pair (AccessDenied / ValidationError / InvalidOperationException) until IAM's role
    and trust-policy propagation clears. Retry the actual dependent call, bounded, instead
    of sleeping blindly and hoping propagation finished in time."""
    while True:
        try:
            return cfn.create_stack_instances(StackSetName=ss_name, Accounts=[account], Regions=[region])[
                "OperationId"
            ]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDenied", "ValidationError", "InvalidOperationException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_stack_instances_with_retry(cfn, ss_name, account, region, timeout_s=180.0, interval_s=10.0):
    """A fresh SELF_MANAGED admin/exec role pair can still be rejected by CloudFormation's own
    internal assume-role attempt for a while after IAM reports the roles as visible -- this
    surfaces as the async operation itself reaching FAILED, not as a synchronous ClientError.
    Clear the failed instance and retry the whole create, bounded by an overall deadline,
    rather than treating one FAILED operation as final."""
    deadline = time.monotonic() + timeout_s
    op_id = _start_create_stack_instances(cfn, ss_name, account, region, deadline, interval_s)
    while True:
        remaining = max(deadline - time.monotonic(), 1.0)
        status = _wait_operation(cfn, ss_name, op_id, timeout_s=remaining)
        if status == "SUCCEEDED" or time.monotonic() >= deadline - interval_s:
            return op_id
        try:
            del_op = cfn.delete_stack_instances(
                StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=False
            )["OperationId"]
            _wait_operation(cfn, ss_name, del_op, timeout_s=max(deadline - time.monotonic(), 1.0))
        except ClientError:
            pass
        time.sleep(interval_s)
        op_id = _start_create_stack_instances(cfn, ss_name, account, region, deadline, interval_s)


def _create_role_retrying(iam, timeout_s=60.0, interval_s=5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(**kwargs)["Role"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "MalformedPolicyDocument" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _ignore_no_such_entity(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_stackset_roles(ctx):
    """Create a per-run SELF_MANAGED admin/exec role pair and register its teardown.
    Pre-existing account-wide roles are never reused."""
    iam = ctx.client("iam")
    admin_role_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_role_name = ctx.unique_name("sim2real-cfn-exec-")
    role_tags = [{"Key": "sim2real", "Value": "delete-nonempty-stackset-rejected"}]

    admin_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust, Tags=role_tags)["Role"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=admin_role_name)))
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
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_role_policy(RoleName=admin_role_name, PolicyName="AssumeStackSetExecRole")
        )
    )

    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
    )
    # A just-created admin role's ARN can briefly be rejected as an invalid
    # principal in another role's trust policy due to IAM propagation lag;
    # retry CreateRole for a bit before giving up.
    _create_role_retrying(iam, RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=exec_role_name)))
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.detach_role_policy(
                RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
        )
    )

    return admin_role["Arn"], exec_role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
