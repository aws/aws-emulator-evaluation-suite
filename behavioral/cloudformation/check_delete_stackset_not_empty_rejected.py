"""delete-stackset-not-empty-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stackset-not-empty-rejected"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a StackSet that still has one or more active stack instances
    must return StackSetNotEmptyException, not delete the StackSet and leave
    the deployed instances orphaned."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_roles(ctx)
    stackset_name = ctx.unique_name("sim2real-behav-ssne-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack_set(cfn, stackset_name))

    region_a = ctx.region
    account_id = roles["account_id"]
    ctx.on_cleanup(lambda: _cleanup_stack_instances(cfn, stackset_name, account_id, [region_a]))

    status = _create_stack_instances_with_retry(cfn, stackset_name, account_id, region_a, timeout_s=240)
    assert status == "SUCCEEDED", f"setup: stack instance deployment did not succeed, status={status}"

    got = _expect_error(lambda: cfn.delete_stack_set(StackSetName=stackset_name))
    expected = ("StackSetNotEmptyException", "StackSet is not empty")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # the rejected delete must not have taken effect: the StackSet still exists
    # and still owns its instance.
    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert any(i["Region"] == region_a and i["Account"] == account_id for i in instances)

    # restore: remove the instance that was blocking deletion, then the
    # identical DeleteStackSet call must now succeed.
    del_op = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a], RetainStacks=False,
    )
    del_status = _wait_stackset_operation(cfn, stackset_name, del_op["OperationId"], timeout_s=300)
    assert del_status == "SUCCEEDED", f"restore: removing the blocking instance did not succeed, status={del_status}"

    cfn.delete_stack_set(StackSetName=stackset_name)

    # independent terminal read at the destination: the StackSet is actually gone.
    gone = _expect_error(lambda: cfn.describe_stack_set(StackSetName=stackset_name))
    expected_gone = ("StackSetNotFoundException", f"StackSet {stackset_name} not found")
    assert gone == expected_gone, f"expected {expected_gone!r}, got {gone!r}"


# ===== helpers =====

def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_role_visible(iam, role_name, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(2)
    raise AssertionError(f"IAM role {role_name} never became visible")


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role_with_principal_retry(iam, role_name, trust_policy, tags=None, timeout_s=240, interval_s=5):
    """create_role() can raise a MalformedPolicyDocument error ("Invalid
    principal in policy") for well beyond just a few seconds after the
    referenced principal role was created, due to IAM eventual consistency
    that can occasionally take a few minutes to clear. Retry within a
    generous bound instead of failing the check on a setup race.

    Note: despite the botocore exception *class* being named
    MalformedPolicyDocumentException, the wire-level Error.Code for this
    failure is actually "MalformedPolicyDocument" (no "Exception" suffix) --
    matching on the wrong string here meant this retry never engaged."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=tags or [])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "MalformedPolicyDocument" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_self_managed_roles(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    admin_role_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_role_name = ctx.unique_name("sim2real-cfn-exec-")

    admin_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    admin_role = iam.create_role(
        RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_role_name))
    admin_role_arn = admin_role["Arn"]
    _wait_role_visible(iam, admin_role_name)

    exec_role_arn = f"arn:aws:iam::{account_id}:role/{exec_role_name}"
    exec_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role_arn}, "Action": "sts:AssumeRole"}],
    })
    # A freshly created IAM role can take a few seconds to become usable as a
    # principal in another role's trust policy; retry past that eventual
    # consistency window instead of treating it as a hard failure.
    _create_role_with_principal_retry(iam, exec_role_name, exec_trust, tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_role(iam, exec_role_name))
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(
        RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")))

    iam.put_role_policy(
        RoleName=admin_role_name,
        PolicyName="AssumeExecRole",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_role_arn}],
        }),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=admin_role_name, PolicyName="AssumeExecRole")))

    _wait_role_visible(iam, admin_role_name)
    _wait_role_visible(iam, exec_role_name)

    return {"account_id": account_id, "admin_role_arn": admin_role_arn, "exec_role_name": exec_role_name}


def _wait_stackset_operation(cfn, stackset_name, operation_id, timeout_s=300, interval_s=5):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=operation_id)["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {operation_id} never reached a terminal state, last={status}")


def _create_stack_instances_with_retry(cfn, stackset_name, account_id, region, timeout_s=240, interval_s=10):
    """CreateStackInstances can accept the request but have its operation end
    FAILED if the self-managed roles have not yet finished IAM propagation
    (CloudFormation could not assume ExecutionRole in time). Retry the actual
    dependent call -- create, wait for a terminal status, and if it did not
    succeed, clear the failed instance and try again -- bounded by an overall
    deadline, rather than sleeping blindly before the first attempt."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        op = cfn.create_stack_instances(StackSetName=stackset_name, Accounts=[account_id], Regions=[region])
        status = _wait_stackset_operation(cfn, stackset_name, op["OperationId"], timeout_s=max(deadline - time.monotonic(), 1))
        if status == "SUCCEEDED":
            return status
        if time.monotonic() >= deadline - interval_s:
            return status
        _cleanup_stack_instances(cfn, stackset_name, account_id, [region])
        time.sleep(interval_s)
    return status


def _cleanup_stack_instances(cfn, stackset_name, account_id, regions):
    try:
        op = cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=regions, RetainStacks=False)
        _wait_stackset_operation(cfn, stackset_name, op["OperationId"], timeout_s=300)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise


def _cleanup_stack_set(cfn, stackset_name):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            cfn.delete_stack_set(StackSetName=stackset_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "StackSetNotFoundException":
                return
            if code != "OperationInProgressException":
                raise
            time.sleep(2)
    raise AssertionError(f"stack set {stackset_name!r} still had an operation in progress after 180 s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
