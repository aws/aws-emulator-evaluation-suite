"""stackset-instances-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-instances-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Stack instances progress CREATE->UPDATE->DELETE and are describable/listable
    throughout, with parameter overrides actually landing on the underlying stack."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_stackset_roles(ctx)
    account_id = roles["account_id"]
    region = ctx.region

    stack_set_name = ctx.unique_name("sim2real-ss-inst-")
    cfn.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=json.dumps(_topic_template()),
        Parameters=[{"ParameterKey": "TopicDisplayName", "ParameterValue": "sim2real-initial"}],
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _cleanup_stackset(ctx, stack_set_name))

    _create_stack_instances_past_role_propagation_lag(cfn, stack_set_name, account_id, region)

    instance = cfn.describe_stack_instance(
        StackSetName=stack_set_name, StackInstanceAccount=account_id, StackInstanceRegion=region
    )["StackInstance"]
    assert instance["Status"] == "CURRENT", f"expected CURRENT after create, got {instance['Status']!r}: {instance}"

    summaries = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    assert any(
        s["Account"] == account_id and s["Region"] == region for s in summaries
    ), f"expected ({account_id}, {region}) among list_stack_instances Summaries, got {summaries}"
    stack_id = instance["StackId"]

    op_id_2 = cfn.update_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=[region],
        ParameterOverrides=[{"ParameterKey": "TopicDisplayName", "ParameterValue": "sim2real-updated"}],
    )["OperationId"]
    _poll_operation(cfn, stack_set_name, op_id_2, timeout_s=300)

    # DescribeStackSetOperation reporting SUCCEEDED does not guarantee that a
    # subsequent DescribeStacks read of the underlying per-instance stack
    # already reflects the new Parameters -- there can be a short,
    # independent eventually-consistent propagation lag between the stack
    # set operation finishing and the underlying stack's own describe
    # results updating. Poll with a bounded timeout to absorb that lag
    # rather than assuming it is negligible. (This only converges at all
    # because TopicDisplayName is now actually Ref'd by the Topic resource
    # below -- an unreferenced parameter change is a real no-op update on
    # AWS and would never converge.)
    def _current_display_name():
        params = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Parameters"]
        return next(p["ParameterValue"] for p in params if p["ParameterKey"] == "TopicDisplayName")

    display_name = _poll_until(
        _current_display_name,
        lambda v: v == "sim2real-updated",
        timeout_s=120,
        interval_s=5,
    )
    assert display_name == "sim2real-updated", f"parameter override did not propagate: {display_name}"

    op_id_3 = cfn.delete_stack_instances(
        StackSetName=stack_set_name, Accounts=[account_id], Regions=[region], RetainStacks=False
    )["OperationId"]
    _poll_operation(cfn, stack_set_name, op_id_3, timeout_s=300)

    remaining = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    assert not any(
        s["Account"] == account_id and s["Region"] == region for s in remaining
    ), f"expected ({account_id}, {region}) gone from list_stack_instances Summaries, got {remaining}"

    deleted_code, deleted_msg = _error_code_and_message(
        lambda: cfn.describe_stack_instance(
            StackSetName=stack_set_name, StackInstanceAccount=account_id, StackInstanceRegion=region
        )
    )
    assert (
        deleted_code == "StackInstanceNotFoundException"
    ), f"expected StackInstanceNotFoundException on the deleted instance, got {deleted_code!r} ({deleted_msg!r})"
    expected_msg = "StackInstance not found"
    assert deleted_msg == expected_msg, f"expected message {expected_msg!r}, got {deleted_msg!r}"


def _topic_template() -> dict:
    # NOTE: TopicDisplayName must actually be wired into a resource property
    # (not just declared). On real AWS, CloudFormation diffs the *resolved*
    # template graph: if a changed parameter value isn't referenced by any
    # resource, there is no observable difference at all, so UpdateStack
    # (and, transitively, UpdateStackInstances) legitimately concludes "no
    # updates are to be performed" and never persists the new parameter
    # value on the stack -- no amount of polling/waiting fixes that, since
    # it isn't a propagation lag, it's a correct no-op. Ref'ing the
    # parameter into the Topic's DisplayName makes the parameter change a
    # real, observable update.
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"TopicDisplayName": {"Type": "String", "Default": "sim2real-default"}},
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"DisplayName": {"Ref": "TopicDisplayName"}},
            }
        },
    }


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "StackSetNotFoundException"):
            raise


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


def _poll_operation(cfn, stack_set_name: str, operation_id: str, timeout_s=300.0, interval_s=5.0) -> dict:
    op = _operation_terminal(cfn, stack_set_name, operation_id, timeout_s, interval_s)
    assert op["Status"] == "SUCCEEDED", f"operation {operation_id} ended as {op['Status']}"
    return op


def _operation_terminal(cfn, stack_set_name: str, operation_id: str, timeout_s=300.0, interval_s=5.0) -> dict:
    """Poll an operation until it leaves RUNNING/QUEUED/STOPPING; raise on timeout."""
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


def _create_stack_instances_past_role_propagation_lag(
    cfn, stack_set_name: str, account_id: str, region: str, attempts: int = 6, delay_s: float = 20.0
) -> dict:
    """The admin/exec roles were just created; CloudFormation assuming
    AdministrationRoleARN for the first time can still race IAM's cross-service
    propagation even after _retry_on_malformed_principal above cleared its own
    window. Retry the actual dependent operation -- the observable signal --
    instead of guessing a wait duration up front. A retry is only taken when
    the failure is on the FIRST attempt and every failed stack instance in the
    operation blames the role/trust wiring specifically; any other failure
    reason is a real defect and must not be swallowed.
    """
    last_op = None
    for attempt in range(attempts):
        op_id = cfn.create_stack_instances(StackSetName=stack_set_name, Accounts=[account_id], Regions=[region])[
            "OperationId"
        ]
        last_op = _operation_terminal(cfn, stack_set_name, op_id, timeout_s=300)
        if last_op["Status"] == "SUCCEEDED":
            return last_op
        if attempt == attempts - 1 or not _all_failures_are_role_propagation_lag(cfn, stack_set_name):
            raise AssertionError(f"operation {op_id} ended as {last_op['Status']}: {last_op}")
        time.sleep(delay_s)
    raise AssertionError(f"create_stack_instances did not succeed within {attempts} attempts: {last_op}")


def _all_failures_are_role_propagation_lag(cfn, stack_set_name: str) -> bool:
    summaries = cfn.list_stack_instances(StackSetName=stack_set_name)["Summaries"]
    failed = [s for s in summaries if s.get("StatusReason")]
    if not failed:
        return False
    reasons = " ".join(s.get("StatusReason", "") for s in failed).lower()
    return "role" in reasons and ("assume" in reasons or "trust" in reasons or "denied" in reasons)


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
    admin_arn = iam.create_role(
        RoleName=admin_name,
        AssumeRolePolicyDocument=json.dumps(admin_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        lambda: iam.create_role(
            RoleName=exec_name,
            AssumeRolePolicyDocument=json.dumps(exec_trust),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
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
