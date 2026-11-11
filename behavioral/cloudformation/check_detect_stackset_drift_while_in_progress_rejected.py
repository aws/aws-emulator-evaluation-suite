"""detect-stackset-drift-while-in-progress-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-stackset-drift-while-in-progress-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetectStackSetDrift succeeds when idle, is rejected with OperationInProgressException and not
    queued while a CreateStackInstances operation runs, and succeeds again once it settles."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_roles(ctx)
    stackset_name = ctx.unique_name("sim2real-behav-driftip-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
    )
    ctx.on_cleanup(lambda: _cleanup_stack_set(cfn, stackset_name))

    account_id = roles["account_id"]
    region_a, region_b = _pick_regions(ctx.region, 2)
    ctx.on_cleanup(lambda: _cleanup_stack_instances(cfn, stackset_name, account_id, [region_a, region_b]))

    # Trust-policy evaluation lags IAM role visibility: the first instance can land FAILED
    # naming the trust relationship, so the helper retries within a bound.
    _create_current_instance(ctx, cfn, stackset_name, account_id, region_a)

    ctrl_op = cfn.detect_stack_set_drift(
        StackSetName=stackset_name, OperationId=ctx.unique_name("op-drift-ctrl-"),
    )
    ctrl_status = _wait_stackset_operation(cfn, stackset_name, ctrl_op["OperationId"], timeout_s=300)
    assert ctrl_status == "SUCCEEDED", (
        f"positive control: DetectStackSetDrift with nothing else running should SUCCEED, "
        f"got {ctrl_status!r}"
    )

    op1 = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_b],
        OperationId=ctx.unique_name("op-create-"),
    )
    # The region_b deployment runs for tens of seconds; confirm it is RUNNING around the call.
    _wait_operation_running(cfn, stackset_name, op1["OperationId"])
    code, message = _error(lambda: cfn.detect_stack_set_drift(
        StackSetName=stackset_name, OperationId=ctx.unique_name("op-drift-"),
    ))
    held = _operation_status(cfn, stackset_name, op1["OperationId"])
    assert held == "RUNNING", f"the blocking operation settled during the refused call: {held}"
    assert code == "OperationInProgressException", f"expected OperationInProgressException, got {code!r}"
    stackset_arn = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["StackSetARN"]
    expected = f"Another Operation on StackSet {stackset_arn} is in progress: {op1['OperationId']}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    ops_during = cfn.list_stack_set_operations(StackSetName=stackset_name)["Summaries"]
    drift_ops_during = [o for o in ops_during if o["Action"] == "DETECT_DRIFT" and o["OperationId"] != ctrl_op["OperationId"]]
    assert drift_ops_during == [], (
        f"a rejected DetectStackSetDrift must not be queued as a real operation: {drift_ops_during}"
    )

    _wait_stackset_operation(cfn, stackset_name, op1["OperationId"], timeout_s=300)

    op2 = cfn.detect_stack_set_drift(
        StackSetName=stackset_name, OperationId=ctx.unique_name("op-drift-restore-"),
    )
    status2 = _wait_stackset_operation(cfn, stackset_name, op2["OperationId"], timeout_s=300)
    assert status2 == "SUCCEEDED", (
        f"DetectStackSetDrift should have been accepted and SUCCEEDED once unblocked, got {status2!r}"
    )


def _pick_regions(exclude, count):
    candidates = [r for r in (
        "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2",
        "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    ) if r != exclude]
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
    """Retry create_role past MalformedPolicyDocument ("Invalid principal in policy"), which IAM
    eventual consistency can cause for minutes after the principal role is created. The wire
    code has no "Exception" suffix, unlike the botocore class name."""
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
