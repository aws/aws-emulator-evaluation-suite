"""stackset-delete-nonempty-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-delete-nonempty-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStackSet on a StackSet that still owns stack instances returns StackSetNotEmptyException;
    once the instances are removed the identical call succeeds and the StackSet is independently
    confirmed gone."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    admin_role_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_role_name = ctx.unique_name("sim2real-cfn-exec-")
    exec_role_arn = f"arn:aws:iam::{account_id}:role/{exec_role_name}"

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
    admin_role_arn = iam.create_role(
        RoleName=admin_role_name,
        AssumeRolePolicyDocument=json.dumps(admin_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_role_name))
    iam.put_role_policy(
        RoleName=admin_role_name,
        PolicyName="assume-exec",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_role_arn}
                ],
            }
        ),
    )

    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": admin_role_arn}, "Action": "sts:AssumeRole"}
        ],
    }
    # IAM validates that a role ARN referenced as a trust-policy principal actually resolves to
    # an existing entity. Since admin_role_arn was just created moments ago, IAM's principal
    # validation can lag behind (eventual consistency) and reject it as "Invalid principal in
    # policy". Retry the actual dependent call (bounded overall) instead of sleeping blindly.
    _create_role_with_retry(
        iam, exec_role_name, json.dumps(exec_trust), tags=[{"Key": "sim2real", "Value": CHECK}],
        timeout_s=60, interval_s=5,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, exec_role_name))
    iam.put_role_policy(
        RoleName=exec_role_name,
        PolicyName="sns-and-cfn",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sns:*"], "Resource": "*"},
                    {"Effect": "Allow", "Action": ["cloudformation:*"], "Resource": "*"},
                ],
            }
        ),
    )

    # Positive control: DeleteStackSet on an EMPTY StackSet (same roles, same permission model,
    # no stack instances) must succeed outright. Without this, "rejects a non-empty StackSet" is
    # indistinguishable from "rejects every DeleteStackSet".
    control_name = ctx.unique_name("sim2real-stackset-control-")
    cfn.create_stack_set(
        StackSetName=control_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack_set(cfn, control_name))
    try:
        cfn.delete_stack_set(StackSetName=control_name)
    except ClientError as err:
        raise AssertionError(
            f"positive control failed: deleting an EMPTY StackSet must succeed, got "
            f"{err.response['Error']['Code']}"
        ) from err
    control_error = _error(lambda: cfn.describe_stack_set(StackSetName=control_name))
    expected_control = ("StackSetNotFoundException", f"StackSet {control_name} not found")
    assert control_error == expected_control, (
        f"positive control: expected the deleted control StackSet to read back "
        f"{expected_control!r}, got {control_error!r}"
    )

    stackset_name = ctx.unique_name("sim2real-stackset-nonempty-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stackset(cfn, stackset_name, account_id, region))

    # Freshly-created IAM roles can take a few seconds to propagate before CloudFormation
    # can assume them. Rather than sleeping blindly, poll by retrying the actual
    # instance-creation call (bounded overall) until the operation lands, clearing out any
    # failed attempt before retrying.
    _create_stack_instances_with_retry(cfn, stackset_name, account_id, region, timeout_s=180)

    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert len(instances) == 1, f"expected 1 stack instance, saw {len(instances)}"

    # Break: delete is rejected while the instance still exists.
    error = _error(lambda: cfn.delete_stack_set(StackSetName=stackset_name))
    expected = ("StackSetNotEmptyException", "StackSet is not empty")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # Effect absent, via an independent read: the rejected delete must not have touched the
    # StackSet or its instance.
    described = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]
    assert described["Status"] == "ACTIVE", (
        f"rejected delete must leave the StackSet ACTIVE, saw {described['Status']}"
    )
    instances_after_reject = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert len(instances_after_reject) == 1, (
        f"rejected delete must leave the stack instance in place, saw "
        f"{len(instances_after_reject)}"
    )

    # Restore: remove the instance that was blocking the delete.
    _delete_stack_instances_and_wait(cfn, stackset_name, account_id, region, timeout_s=240)
    instances_after_restore = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert len(instances_after_restore) == 0, (
        f"expected no stack instances after restore, saw {len(instances_after_restore)}"
    )

    # The identical call now succeeds.
    try:
        cfn.delete_stack_set(StackSetName=stackset_name)
    except ClientError as err:
        raise AssertionError(
            f"expected delete_stack_set to succeed once the instance was removed, got "
            f"{err.response['Error']['Code']}"
        ) from err

    # Terminal read: independent of the mutating call, at the destination.
    final_error = _error(lambda: cfn.describe_stack_set(StackSetName=stackset_name))
    expected_final = ("StackSetNotFoundException", f"StackSet {stackset_name} not found")
    assert final_error == expected_final, (
        f"expected the restored-then-deleted StackSet to read back {expected_final!r}, "
        f"got {final_error!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


def _safe_delete_stack_set(cfn, name):
    try:
        cfn.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


def _create_role_with_retry(iam, role_name, trust_policy_json, tags=None, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_policy_json,
                Tags=tags or [],
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_stackset_operation(cfn, stackset_name, op_id, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=op_id
        )["StackSetOperation"]["Status"]
        if status not in ("RUNNING", "QUEUED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not finish in {timeout_s}s (last={status})")


def _poll_operation_until_terminal(cfn, stackset_name, op_id, deadline, interval_s=5.0):
    """Poll a stack-set operation to a terminal status, bounded by an absolute deadline.

    Unlike ``_wait_for_stackset_operation`` this never raises on timeout -- it just returns
    the last observed status (which may still be RUNNING/QUEUED) so the caller can decide
    whether to retry.
    """
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=op_id
        )["StackSetOperation"]["Status"]
        if status not in ("RUNNING", "QUEUED"):
            return status
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0)))
    return status


def _create_stack_instances_with_retry(
    cfn, stackset_name, account_id, region, timeout_s=180.0, interval_s=10.0
):
    """Create stack instances, retrying (bounded by ``timeout_s``) if an attempt fails --
    e.g. because the freshly created IAM administration/execution roles haven't finished
    propagating yet, a well-known AWS eventual-consistency window. This polls the actual
    dependent action to a real condition (the operation reaching SUCCEEDED, or the overall
    deadline expiring) instead of sleeping blindly.

    Returns the final observed operation status.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        op_id = cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
        )["OperationId"]
        status = _poll_operation_until_terminal(cfn, stackset_name, op_id, deadline)
        if status == "SUCCEEDED":
            return status
        # Only clear the failed instance and retry if there's still enough of the bound left
        # to usefully recreate it -- otherwise leave the (failed-but-existing) instance in
        # place rather than risk ending the loop with it deleted and nothing recreated.
        remaining = deadline - time.monotonic()
        if remaining <= interval_s:
            return status
        try:
            del_op_id = cfn.delete_stack_instances(
                StackSetName=stackset_name,
                Accounts=[account_id],
                Regions=[region],
                RetainStacks=False,
            )["OperationId"]
            _poll_operation_until_terminal(cfn, stackset_name, del_op_id, deadline)
        except Exception:
            pass
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0)))
    return status


def _delete_stack_instances_and_wait(cfn, stackset_name, account_id, region, timeout_s=240.0):
    op_id = cfn.delete_stack_instances(
        StackSetName=stackset_name,
        Accounts=[account_id],
        Regions=[region],
        RetainStacks=False,
    )["OperationId"]
    status = _wait_for_stackset_operation(cfn, stackset_name, op_id, timeout_s=timeout_s)
    assert status == "SUCCEEDED", f"expected instance removal to succeed, status={status}"


def _cleanup_stackset(cfn, stackset_name, account_id, region):
    try:
        op_id = cfn.delete_stack_instances(
            StackSetName=stackset_name,
            Accounts=[account_id],
            Regions=[region],
            RetainStacks=False,
        )["OperationId"]
        _wait_for_stackset_operation(cfn, stackset_name, op_id, timeout_s=240)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise
    try:
        cfn.delete_stack_set(StackSetName=stackset_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
