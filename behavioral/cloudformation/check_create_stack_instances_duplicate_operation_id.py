"""create-stack-instances-duplicate-operation-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-instances-duplicate-operation-id"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Submitting CreateStackInstances twice with the same OperationId but different target Regions
    must return OperationIdAlreadyExistsException instead of accepting the second request as a new
    operation."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_roles(ctx)
    stackset_name = ctx.unique_name("sim2real-behav-opid-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
    )
    ctx.on_cleanup(lambda: _cleanup_stack_set(cfn, stackset_name))

    region_a = ctx.region
    region_b = _other_region(ctx.region)
    ctx.on_cleanup(lambda: _cleanup_stack_instances(cfn, stackset_name, roles["account_id"], [region_a]))

    # Any non-SUCCEEDED operation (typically the new roles still propagating in IAM) is cleaned up
    # and resubmitted to a deadline; the final status is still asserted below.
    left = ctx.time_left()
    deadline = time.monotonic() + (240.0 if left is None else min(240.0, left))
    while True:
        op_id = ctx.unique_name("op-")
        resp = cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[roles["account_id"]], Regions=[region_a], OperationId=op_id,
        )
        assert resp["OperationId"] == op_id, f"expected the echoed OperationId to be {op_id!r}, got {resp['OperationId']!r}"

        # Same OperationId, but a genuinely different request (a different target
        # region) while the first operation is still tracked/running.
        code, message = _error(lambda: cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[roles["account_id"]], Regions=[region_b], OperationId=op_id,
        ))
        assert code == "OperationIdAlreadyExistsException", f"expected OperationIdAlreadyExistsException, got {code!r}"
        expected = f"Operation with Id {op_id} already exists"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

        status = _wait_stackset_operation(cfn, stackset_name, op_id, timeout_s=300)
        if status == "SUCCEEDED" or time.monotonic() >= deadline:
            break
        _cleanup_stack_instances(cfn, stackset_name, roles["account_id"], [region_a])
        time.sleep(2)
    assert status == "SUCCEEDED", f"expected the original operation {op_id} to complete despite the rejected duplicate, got {status!r}"

    # The rejected duplicate must never have taken effect: only region_a, the
    # target of the original (accepted) request, may show up as a provisioned
    # stack instance.
    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    regions_present = {i["Region"] for i in instances}
    assert regions_present == {region_a}, (
        f"expected only {region_a!r} to have a provisioned stack instance, got {regions_present!r}"
    )


# ===== helpers =====

def _other_region(region):
    for candidate in ("us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"):
        if candidate != region:
            return candidate
    return "us-east-2"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. A call that
    succeeds raises AssertionError: the target accepted what AWS refuses."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _create_role_with_principal_retry(iam, role_name, trust_policy, timeout_s=240, interval_s=5):
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
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "MalformedPolicyDocument" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_self_managed_roles(ctx):
    """Sets up a throwaway SELF_MANAGED StackSets admin/execution role pair
    targeting this same account, and registers their teardown."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    admin_role_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_role_name = ctx.unique_name("sim2real-cfn-exec-")

    admin_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust)["Role"]
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
    _create_role_with_principal_retry(iam, exec_role_name, exec_trust)
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


def _cleanup_stack_instances(cfn, stackset_name, account_id, regions):
    try:
        op = cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=regions, RetainStacks=False)
        _wait_stackset_operation(cfn, stackset_name, op["OperationId"], timeout_s=300)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
            "StackInstanceNotFoundException",
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
