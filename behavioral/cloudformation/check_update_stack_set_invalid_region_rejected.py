"""update-stack-set-invalid-region-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-stack-set-invalid-region-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances with a valid region plus a non-existent region is rejected wholesale
    (nothing deployed to the valid region); the same call with only the valid region succeeds."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    admin_arn, exec_role_name = _create_admin_execution_roles(ctx)

    stack_set_name = ctx.unique_name("sim2real-cfn-ss-")
    cfn.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real-behav", "Value": "ssregion"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack_set(ctx, stack_set_name))

    valid_region = ctx.region
    bogus_region = "not-a-real-region-1"
    error = _error(
        lambda: cfn.create_stack_instances(
            StackSetName=stack_set_name,
            Accounts=[account_id],
            Regions=[valid_region, bogus_region],
        )
    )
    expected = ("ValidationError", f"Region {bogus_region} is not supported")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # (b) effect absent: nothing was deployed to the valid region either -- the whole
    # request was rejected, not partially applied.
    instances = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    assert instances == [], f"expected no stack instances after rejected call, got {instances}"

    # (c) positive control: the identical call with only the valid region succeeds. Freshly
    # created SELF_MANAGED admin/execution role trust relationships can take a little while to
    # propagate to the StackSets control plane, so retry the whole create-then-wait sequence a
    # few times if it fails specifically because the trust relationship wasn't yet visible.
    op_status, instances2 = _create_instances_until_ready(ctx, stack_set_name, account_id, valid_region)
    assert op_status == "SUCCEEDED", f"expected stack set operation to SUCCEED, got {op_status}: {instances2}"
    assert len(instances2) == 1 and instances2[0]["Status"] == "CURRENT", (
        f"expected exactly one CURRENT stack instance, got {instances2}"
    )

    # (d) terminal delete, proven gone via an independent read rather than left unasserted.
    del_op = cfn.delete_stack_instances(
        StackSetName=stack_set_name, Accounts=[account_id], Regions=[valid_region], RetainStacks=False
    )["OperationId"]
    del_status = _wait_stack_set_operation(ctx, stack_set_name, del_op)
    assert del_status == "SUCCEEDED", f"expected delete_stack_instances to SUCCEED, got {del_status}"
    remaining = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    assert remaining == [], f"expected no stack instances after delete, got {remaining}"


def _error(fn):
    """Call fn() and return the botocore (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_admin_execution_roles(ctx):
    iam = ctx.client("iam")
    admin_role_name = ctx.unique_name("sim2real-cfn-ss-admin-")
    exec_role_name = ctx.unique_name("sim2real-cfn-ss-exec-")

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    admin_role = iam.create_role(
        RoleName=admin_role_name,
        AssumeRolePolicyDocument=json.dumps(admin_trust),
        Tags=[{"Key": "sim2real-behav", "Value": "ssregion"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, admin_role_name))
    admin_arn = admin_role["Arn"]

    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}],
    }
    _create_role_with_retry(ctx, exec_role_name, exec_trust)
    ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": f"arn:aws:iam::*:role/{exec_role_name}",
            }
        ],
    }
    iam.put_role_policy(RoleName=admin_role_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(admin_policy))
    return admin_arn, exec_role_name


def _create_role_with_retry(ctx, role_name, trust_policy, timeout_s=60.0, interval_s=3.0):
    """A trust policy referencing a just-created IAM role ARN as its Principal can
    transiently fail with MalformedPolicyDocument until the role has propagated."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "sim2real-behav", "Value": "ssregion"}],
            )["Role"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_role({role_name}) never succeeded, last error={last_err}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_instances_with_retry(ctx, stack_set_name, account_id, region, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.create_stack_instances(StackSetName=stack_set_name, Accounts=[account_id], Regions=[region])
            return resp["OperationId"]
        except ClientError as exc:
            # Freshly created IAM roles can take a few seconds to become assumable.
            last_err = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"create_stack_instances never succeeded, last error={last_err}")


def _create_instances_until_ready(ctx, stack_set_name, account_id, region, attempts=4, backoff_s=20.0):
    cfn = ctx.client("cloudformation")
    last_status = None
    last_instances = None
    for attempt in range(attempts):
        op_id = _create_instances_with_retry(ctx, stack_set_name, account_id, region)
        last_status = _wait_stack_set_operation(ctx, stack_set_name, op_id)
        last_instances = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
        if last_status == "SUCCEEDED":
            return last_status, last_instances
        # Clear the failed instance record so the next attempt starts clean, then back off to
        # let the IAM trust relationship propagate before retrying.
        if last_instances:
            cfn.delete_stack_instances(
                StackSetName=stack_set_name, Accounts=[account_id], Regions=[region], RetainStacks=False
            )
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]:
                time.sleep(5)
        time.sleep(backoff_s)
    return last_status, last_instances


def _wait_stack_set_operation(ctx, stack_set_name, operation_id, timeout_s=240.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)[
            "StackSetOperation"
        ]["Status"]
        if last in ("SUCCEEDED", "FAILED", "STOPPED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {operation_id} never reached a terminal state, last={last}")


def _safe_delete_stack_set(ctx, stack_set_name):
    cfn = ctx.client("cloudformation")
    try:
        summaries = cfn.list_stack_instances(StackSetName=stack_set_name).get("Summaries", [])
        if summaries:
            accounts = sorted({s["Account"] for s in summaries})
            regions = sorted({s["Region"] for s in summaries})
            cfn.delete_stack_instances(
                StackSetName=stack_set_name, Accounts=accounts, Regions=regions, RetainStacks=False
            )
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                if not cfn.list_stack_instances(StackSetName=stack_set_name).get("Summaries", []):
                    break
                time.sleep(5)
        cfn.delete_stack_set(StackSetName=stack_set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
