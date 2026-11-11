"""concurrent-stackset-update-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-stackset-update-rejected"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Issuing UpdateStackSet while a prior CreateStackInstances operation on
    the same StackSet is still running must be rejected instead of starting
    a second operation."""
    cfn = ctx.client("cloudformation")
    roles = _create_self_managed_roles(ctx)
    stackset_name = ctx.unique_name("sim2real-behav-ssupd-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}})
    _create_stack_set_with_role_retry(
        cfn,
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=roles["admin_role_arn"],
        ExecutionRoleName=roles["exec_role_name"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack_set(cfn, stackset_name))

    region_pool = _pick_regions(ctx.region, 6)
    region_a, race_regions = region_pool[0], region_pool[1:]
    account_id = roles["account_id"]
    used_regions = [region_a] + race_regions
    ctx.on_cleanup(lambda: _cleanup_stack_instances(cfn, stackset_name, account_id, used_regions))

    # Establish a stable baseline instance first. Racing the very *first*
    # ever operation on a brand new StackSet against a second call is
    # unreliable: real CloudFormation appears to need a brief head start
    # after the first-ever operation on a StackSet before its
    # single-operation-at-a-time lock is consistently visible to a
    # concurrently-issued write, so an immediate race right after StackSet
    # creation can occasionally let the second call slip through before the
    # lock is observed. Establishing a baseline instance and waiting for it
    # to settle before ever racing a second operation avoids this.
    op0 = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region_a],
        OperationId=ctx.unique_name("op-base-"),
    )
    _wait_stackset_operation(cfn, stackset_name, op0["OperationId"], timeout_s=300)

    # Now start a *second* stack-instance deployment -- this holds the
    # StackSet's single-operation-at-a-time lock while it runs -- and,
    # without waiting for it to settle, race an UpdateStackSet against the
    # same StackSet.
    #
    # A single-region CreateStackInstances deploying one trivial SNS Topic
    # settles so fast server-side that a single immediate sample of the
    # race can slip straight through with no conflict at all: by the time
    # the racing UpdateStackSet call is actually issued, the CreateStackInstances
    # operation has sometimes already reached a terminal state. Racing a
    # per-region retry loop against that same fast operation doesn't fix
    # this -- each fresh attempt is just as likely to complete before the
    # race lands. Instead, widen the race window itself: deploy into *all*
    # of the race regions in a single CreateStackInstances call, with
    # OperationPreferences forcing a strictly sequential (MaxConcurrentCount=1)
    # per-region rollout. That makes the whole operation take several times
    # as long as a single region would (each region is fully provisioned,
    # one after another, before the operation reaches a terminal state),
    # giving a comfortably large -- and still real -- window in which the
    # StackSet's single-operation-at-a-time lock is reliably observable to
    # a concurrently issued UpdateStackSet.
    updated_template = json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Topic2": {"Type": "AWS::SNS::Topic", "Properties": {}},
        },
    })
    op1 = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=race_regions,
        OperationId=ctx.unique_name("op-create-"),
        OperationPreferences={
            "MaxConcurrentCount": 1,
            "FailureToleranceCount": len(race_regions),
        },
    )
    code, message = _race_update_stack_set(
        ctx, cfn, stackset_name, op1["OperationId"], updated_template,
        roles["admin_role_arn"], roles["exec_role_name"],
        spin_timeout_s=180, interval_s=0.5,
    )

    # Real CloudFormation rejects this exact conflict -- UpdateStackSet
    # racing a still-running CreateStackInstances operation on the same
    # StackSet -- with OperationInProgressException, the same code the
    # sibling detect-stack-set-drift-while-in-progress and
    # concurrent-stack-instance-update checks observe for *their* respective
    # APIs. The message names the specific running operation by id, so
    # require that rather than a generic "in progress" wording -- a target
    # that returns the right code with an unrelated message would otherwise
    # still pass.
    assert code == "OperationInProgressException", (
        f"expected OperationInProgressException, got {code!r} ({message!r})"
    )
    stackset_arn = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["StackSetARN"]
    expected = f"Another Operation on StackSet {stackset_arn} is in progress: {op1['OperationId']}"
    assert message == expected, (
        f"OperationInProgressException message must name the running operation "
        f"{op1['OperationId']!r}: expected {expected!r}, got {message!r}"
    )

    # The rejected call must have had no effect: the StackSet's template must
    # still be the original one, not the one the rejected UpdateStackSet
    # carried.
    rejected_template = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["TemplateBody"]
    assert "Topic2" not in rejected_template, (
        f"rejected UpdateStackSet must not have taken effect, but the StackSet template already "
        f"contains Topic2: {rejected_template!r}"
    )

    _wait_stackset_operation(cfn, stackset_name, op1["OperationId"], timeout_s=600)

    # Restore: with the conflicting operation now terminal, the identical
    # UpdateStackSet call must succeed -- proving the earlier rejection was
    # this specific point-in-time conflict, not this StackSet or this target
    # rejecting UpdateStackSet outright.
    op2 = cfn.update_stack_set(
        StackSetName=stackset_name, TemplateBody=updated_template,
        AdministrationRoleARN=roles["admin_role_arn"], ExecutionRoleName=roles["exec_role_name"],
        OperationId=ctx.unique_name("op-update-retry-"),
    )
    retry_status = _wait_stackset_operation(cfn, stackset_name, op2["OperationId"], timeout_s=600)
    assert retry_status == "SUCCEEDED", (
        f"identical UpdateStackSet must succeed once the conflicting operation has settled, "
        f"got {retry_status!r}"
    )
    accepted_template = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["TemplateBody"]
    assert "Topic2" in accepted_template, (
        f"UpdateStackSet reported {retry_status!r} but the StackSet template was not updated: "
        f"{accepted_template!r}"
    )


# ===== helpers =====

def _pick_regions(exclude, count):
    candidates = [r for r in (
        "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2",
        "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        "ap-northeast-2", "ap-south-1", "sa-east-1", "ca-central-1",
    ) if r != exclude]
    return candidates[:count]


def _race_update_stack_set(
    ctx, cfn, stackset_name, running_op_id, template, admin_role_arn, exec_role_name,
    spin_timeout_s=25, interval_s=1.0,
):
    """Tightly re-issue UpdateStackSet while a given CreateStackInstances
    operation is still running, until either the observed operation-in-
    progress rejection is seen or the running operation itself settles to
    a terminal state (at which point this attempt's race window has
    definitively closed and a fresh attempt, with a fresh running
    operation, is needed). A window that closes with every UpdateStackSet
    accepted raises AssertionError: the target never refused the conflict.

    A SELF_MANAGED StackSet's UpdateStackSet call must re-carry
    AdministrationRoleARN/ExecutionRoleName on every call -- CloudFormation
    does not persist them across calls -- or it rejects with a ValidationError
    asking for the role, which is indistinguishable by code from the
    concurrency rejection this check exists to detect."""
    deadline = time.monotonic() + spin_timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            cfn.update_stack_set(
                StackSetName=stackset_name, TemplateBody=template,
                AdministrationRoleARN=admin_role_arn, ExecutionRoleName=exec_role_name,
                OperationId=ctx.unique_name("op-update-"),
            )
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=running_op_id)["StackSetOperation"]["Status"]
        if status not in ("RUNNING", "QUEUED", "STOPPING"):
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"UpdateStackSet was accepted while operation {running_op_id} was running "
        f"(last operation status {status!r}); expected OperationInProgressException"
    )


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
            iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _create_stack_set_with_role_retry(cfn, timeout_s=120, interval_s=5, **kwargs):
    """create_stack_set() can be rejected because the just-created
    administration/execution role trust hasn't propagated through IAM yet;
    retry within a generous bound instead of a fixed sleep before the call."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cfn.create_stack_set(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "AccessDenied", "ValidationError", "InvalidOperationException",
            ) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


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
            StackSetName=stackset_name, Accounts=[account_id], Regions=regions, RetainStacks=False,
            OperationPreferences={
                "RegionConcurrencyType": "PARALLEL",
                "MaxConcurrentCount": len(regions),
                "FailureToleranceCount": len(regions) - 1,
            },
        )
        _wait_stackset_operation(cfn, stackset_name, op["OperationId"], timeout_s=900)
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
