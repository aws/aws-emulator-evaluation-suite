"""stackset-concurrent-operation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-concurrent-operation-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a stack set operation is RUNNING, a concurrent UpdateStackSet on the same stack set
    is rejected with OperationInProgressException naming the running operation, not silently queued."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_stackset_roles(ctx)
    account_id = roles["account_id"]
    # A StackSet operation is deployed across a Regions list, not ctx.region; three
    # concrete regions (rather than one) are required so the SEQUENTIAL rollout below
    # takes long enough to give the concurrent probe a real window to land in.
    regions = ["us-east-1", "us-east-2", "us-west-2"]

    stack_set_name = ctx.unique_name("sim2real-ss-contend-")
    template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}}
    )
    stack_set_id = _retry_on_role_not_yet_assumable(
        lambda: cfn.create_stack_set(
            StackSetName=stack_set_name,
            TemplateBody=template,
            PermissionModel="SELF_MANAGED",
            AdministrationRoleARN=roles["admin_role_arn"],
            ExecutionRoleName=roles["exec_role_name"],
            Tags=[{"Key": "sim2real-check", "Value": "stackset-concurrent-operation-rejected"}],
        )
    )["StackSetId"]
    ctx.on_cleanup(lambda: _cleanup_stackset(ctx, stack_set_name))

    op_id = cfn.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=regions,
        OperationPreferences={"RegionConcurrencyType": "SEQUENTIAL", "FailureToleranceCount": 3},
    )["OperationId"]

    # One concurrent call can miss the lock window of a fast rollout, so keep probing while
    # the first operation is non-terminal.
    code, msg = None, None
    attempt = 0
    op = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=op_id)["StackSetOperation"]
    poll_deadline = time.monotonic() + 420
    while op["Status"] in ("RUNNING", "QUEUED", "STOPPING"):
        attempt += 1
        # Vary each probe's payload: an identical retry after one probe lands fails with the
        # unrelated no-op ValidationError "No updates are to be performed".
        code, msg = _client_error(
            lambda attempt=attempt: cfn.update_stack_set(
                StackSetName=stack_set_name,
                TemplateBody=template,
                Description=f"sim2real-contention-probe-{attempt}",
                AdministrationRoleARN=roles["admin_role_arn"],
                ExecutionRoleName=roles["exec_role_name"],
            )
        )
        if code == _ACCEPTED:
            raise AssertionError(
                f"expected the concurrent UpdateStackSet to be rejected with OperationInProgressException "
                f"while operation {op_id} was {op['Status']}, but it was accepted as operation {msg}"
            )
        if (code, msg) == _NON_SIGNAL:
            code, msg = None, None
        else:
            break
        if time.monotonic() > poll_deadline:
            break
        time.sleep(2)
        op = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=op_id)["StackSetOperation"]

    op = _poll_operation_terminal(cfn, stack_set_name, op_id, timeout_s=420)
    if code is None:
        # Only valid when the sequential rollout was already terminal before any
        # concurrent call was sent; then confirm it completed cleanly.
        assert attempt == 0, (
            f"sent {attempt} concurrent UpdateStackSet probes while operation {op_id} was non-terminal "
            "and none was rejected with OperationInProgressException"
        )
        assert op["Status"] == "SUCCEEDED", (
            f"expected the un-raced rollout to finish SUCCEEDED, got {op['Status']}: {op}"
        )
    else:
        partition = roles["admin_role_arn"].split(":")[1]
        stack_set_arn = f"arn:{partition}:cloudformation:{ctx.region}:{account_id}:stackset/{stack_set_id}"
        expected = f"Another Operation on StackSet {stack_set_arn} is in progress: {op_id}"
        assert (code, msg) == ("OperationInProgressException", expected), (
            f"expected OperationInProgressException {expected!r} for the concurrent UpdateStackSet, "
            f"got {code} {msg!r}"
        )

        # Restore: the same call succeeds once the blocking operation settles, so the
        # conflict was transient.
        restore_op_id = cfn.update_stack_set(
            StackSetName=stack_set_name,
            TemplateBody=template,
            Description="sim2real-contention-probe-restore",
            AdministrationRoleARN=roles["admin_role_arn"],
            ExecutionRoleName=roles["exec_role_name"],
        )["OperationId"]
        restore_op = _poll_operation_terminal(cfn, stack_set_name, restore_op_id, timeout_s=420)
        assert restore_op["Status"] == "SUCCEEDED", (
            f"expected UpdateStackSet to succeed once the lock cleared, got {restore_op['Status']}: {restore_op}"
        )


_NON_SIGNAL = ("<no concurrency signal>", None)
_ACCEPTED = "<accepted>"


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises,
    (_ACCEPTED, OperationId) when the call succeeds, or _NON_SIGNAL (whose code no error
    code equals) when it is refused only as a no-op update."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        code = err["Code"]
        message = err.get("Message", "")
        if code == "ValidationError" and "No updates are to be performed" in message:
            # The probe's content already matches the stack set (an earlier probe applied);
            # that says nothing about concurrency, so keep probing.
            return _NON_SIGNAL
        return code, message
    return _ACCEPTED, result.get("OperationId")


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


def _retry_on_role_not_yet_assumable(fn, timeout_s: float = 120.0, interval_s: float = 10.0):
    """Retry fn while CloudFormation's role-assumption path lags IAM's own consistency.
    The first call that assumes a fresh role can briefly fail with a role/principal error."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            role_related = "role" in message or "assume" in message or "principal" in message
            if role_related and code in (
                "ValidationError",
                "InvalidParameterValueException",
                "AccessDenied",
                "InsufficientCapabilitiesException",
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _wait_role_visible(iam, role_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"IAM role {role_name} never became visible within {timeout_s}s")


def _wait_inline_policy_visible(
    iam, role_name: str, policy_name: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"inline policy {policy_name} on role {role_name} never became visible within {timeout_s}s")


def _create_self_managed_stackset_roles(ctx) -> dict:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-cfn-exec-")
    resource_tags = [{"Key": "sim2real-check", "Value": "stackset-concurrent-operation-rejected"}]

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    admin_arn = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=resource_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=admin_name)))
    _wait_role_visible(iam, admin_name)

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
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust), Tags=resource_tags)
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=exec_name)))
    _wait_role_visible(iam, exec_name)

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
    _wait_inline_policy_visible(iam, admin_name, "AssumeExecRole")

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
