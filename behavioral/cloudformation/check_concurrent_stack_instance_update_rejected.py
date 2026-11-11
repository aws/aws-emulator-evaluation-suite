"""concurrent-stack-instance-update-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-stack-instance-update-rejected"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStackInstances and DeleteStackInstances on another Region are rejected with
    OperationInProgressException and no effect while a StackSet operation runs; once it settles,
    the same calls are accepted and take effect."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_roles(ctx)
    stackset_name = ctx.unique_name("sim2real-behav-siupd-")
    template = json.dumps({
        "Parameters": {"TagValue": {"Type": "String", "Default": "v1"}},
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"Tags": [{"Key": "sim2real-behav", "Value": {"Ref": "TagValue"}}]},
            },
        },
    })
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack_set(cfn, stackset_name))
    account_id = roles["account_id"]
    stackset_arn = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["StackSetARN"]

    region_a, region_b, region_c = _pick_regions(ctx.region, 3)
    ctx.on_cleanup(lambda: _cleanup_stack_instances(cfn, stackset_name, account_id, [region_a], [region_b, region_c]))

    # Trust-policy evaluation lags IAM role visibility: the first instance can land FAILED
    # naming the trust relationship, so the helper retries within a bound.
    baseline = _create_current_instance(ctx, cfn, stackset_name, account_id, region_a)
    assert not baseline.get("ParameterOverrides"), (
        f"baseline instance should carry no overrides yet: {baseline.get('ParameterOverrides')}"
    )

    update_overrides = [{"ParameterKey": "TagValue", "ParameterValue": "v2"}]

    op1 = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_b],
        OperationId=ctx.unique_name("op-b-"),
    )
    # The region_b deployment runs for tens of seconds; confirm it is RUNNING around the call.
    _wait_operation_running(cfn, stackset_name, op1["OperationId"])
    code_update, msg_update = _error(lambda: cfn.update_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a],
        ParameterOverrides=update_overrides, OperationId=ctx.unique_name("op-upd-"),
    ))
    held = _operation_status(cfn, stackset_name, op1["OperationId"])
    assert held == "RUNNING", f"the blocking operation settled during the refused call: {held}"
    assert code_update == "OperationInProgressException", (
        f"UpdateStackInstances: expected OperationInProgressException, got {code_update!r}"
    )
    expected = f"Another Operation on StackSet {stackset_arn} is in progress: {op1['OperationId']}"
    assert msg_update == expected, f"expected {expected!r}, got {msg_update!r}"
    blocked = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region_a,
    )["StackInstance"]
    assert not blocked.get("ParameterOverrides"), (
        f"a rejected UpdateStackInstances must not have taken effect: {blocked.get('ParameterOverrides')}"
    )
    _wait_stackset_operation(cfn, stackset_name, op1["OperationId"], timeout_s=300)

    op1_restore = cfn.update_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a],
        ParameterOverrides=update_overrides, OperationId=ctx.unique_name("op-upd-restore-"),
    )
    _wait_stackset_operation(cfn, stackset_name, op1_restore["OperationId"], timeout_s=300)
    restored = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region_a,
    )["StackInstance"]
    applied = [p for p in restored.get("ParameterOverrides") or []
               if p.get("ParameterKey") == "TagValue" and p.get("ParameterValue") == "v2"]
    assert applied, (
        f"UpdateStackInstances should have applied once unblocked, got {restored.get('ParameterOverrides')}"
    )

    op2 = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_c],
        OperationId=ctx.unique_name("op-c-"),
    )
    _wait_operation_running(cfn, stackset_name, op2["OperationId"])
    code_delete, msg_delete = _error(lambda: cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a], RetainStacks=False,
        OperationId=ctx.unique_name("op-del-"),
    ))
    held = _operation_status(cfn, stackset_name, op2["OperationId"])
    assert held == "RUNNING", f"the blocking operation settled during the refused call: {held}"
    assert code_delete == "OperationInProgressException", (
        f"DeleteStackInstances: expected OperationInProgressException, got {code_delete!r}"
    )
    expected = f"Another Operation on StackSet {stackset_arn} is in progress: {op2['OperationId']}"
    assert msg_delete == expected, f"expected {expected!r}, got {msg_delete!r}"
    still_there = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region_a,
    )["StackInstance"]
    assert still_there["StackId"] == restored["StackId"], (
        "a rejected DeleteStackInstances must not have removed the instance"
    )
    _wait_stackset_operation(cfn, stackset_name, op2["OperationId"], timeout_s=300)

    op2_restore = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a], RetainStacks=False,
        OperationId=ctx.unique_name("op-del-restore-"),
    )
    _wait_stackset_operation(cfn, stackset_name, op2_restore["OperationId"], timeout_s=300)
    not_found, msg_nf = _error(lambda: cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region_a,
    ))
    assert not_found == "StackInstanceNotFoundException", (
        f"DeleteStackInstances should have removed the instance once unblocked, got {not_found!r}"
    )
    assert msg_nf == "StackInstance not found", msg_nf


def _pick_regions(exclude, count):
    candidates = [r for r in ("us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "eu-central-1")
                  if r != exclude]
    return candidates[:count]


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


def _operation_status(cfn, stackset_name, operation_id):
    return cfn.describe_stack_set_operation(
        StackSetName=stackset_name, OperationId=operation_id)["StackSetOperation"]["Status"]


def _wait_operation_running(cfn, stackset_name, operation_id, timeout_s=60, interval_s=1):
    """Poll until the operation is RUNNING; raise if it settles first or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _operation_status(cfn, stackset_name, operation_id)
        if status == "RUNNING":
            return
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            raise AssertionError(
                f"operation {operation_id} settled ({status}) before the window could be used")
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} never reached RUNNING, last={status}")


def _create_current_instance(ctx, cfn, stackset_name, account_id, region, attempts=6, delay_s=20.0):
    """Create a stack instance in `region`, retrying past a transient trust-relationship FAILED
    instance (deleting it first) until it is CURRENT or fails for another reason."""
    last_reason = None
    for attempt in range(attempts):
        op = cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[region],
            OperationId=ctx.unique_name("op-base-"),
        )
        _wait_stackset_operation(cfn, stackset_name, op["OperationId"], timeout_s=300)
        instance = cfn.describe_stack_instance(
            StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region,
        )["StackInstance"]
        if instance["Status"] == "CURRENT":
            return instance
        last_reason = instance.get("StatusReason", "")
        if "trust relationship" not in last_reason.lower() or attempt == attempts - 1:
            raise AssertionError(f"baseline instance did not become CURRENT: {instance}")
        try:
            cleanup_op = cfn.delete_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region], RetainStacks=False)
            _wait_stackset_operation(cfn, stackset_name, cleanup_op["OperationId"], timeout_s=120)
        except ClientError:
            pass
        time.sleep(delay_s)
    raise AssertionError(f"baseline instance never became CURRENT; last reason: {last_reason!r}")


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


def _create_role_with_principal_retry(iam, role_name, trust_policy, resource_tags, timeout_s=240, interval_s=5):
    """Retry create_role past MalformedPolicyDocument ("Invalid principal in policy"), which IAM
    eventual consistency can cause for minutes after the principal role is created. The wire
    code has no "Exception" suffix, unlike the botocore class name."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=resource_tags)
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
    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    admin_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    admin_role = iam.create_role(
        RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust, Tags=resource_tags,
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_role_name))
    admin_role_arn = admin_role["Arn"]
    _wait_role_visible(iam, admin_role_name)

    exec_role_arn = f"arn:aws:iam::{account_id}:role/{exec_role_name}"
    exec_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role_arn}, "Action": "sts:AssumeRole"}],
    })
    _create_role_with_principal_retry(iam, exec_role_name, exec_trust, resource_tags)
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


def _cleanup_stack_instances(cfn, stackset_name, account_id, *region_groups):
    # One call per group: region_a may already be deleted, and a combined call naming an
    # absent region can fail atomically and strand the others.
    for regions in region_groups:
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
