"""delete-nonempty-stack-set-fails."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonempty-stack-set-fails"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises instead of returning a falsy sentinel, so acceptance is never mistaken for a
    bare code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=300, interval_s=3):
    """Poll DescribeStackSetOperation until Status is in targets; return the operation dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]
        if op.get("Status") in target:
            return op
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not reach {target} (last={op.get('Status') if op else None!r})")

def _topic_template(topic_name=None, extra_tag=None):
    props = {}
    if topic_name:
        props["TopicName"] = topic_name
    if extra_tag:
        props["Tags"] = [{"Key": "probe", "Value": extra_tag}]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })

def _create_role_retrying_principal(iam, timeout_s=60.0, interval_s=5.0, **kwargs):
    """create_role() with an AWS-principal trust doc can transiently raise
    MalformedPolicyDocument ("Invalid principal in policy") for a few seconds after the
    referenced role was created, due to IAM propagation lag. Retry the actual dependent
    call, bounded, instead of sleeping blindly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "MalformedPolicyDocument" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _create_stack_instances_with_retry(cf, ss_name, accounts, regions, timeout_s=180.0, interval_s=10.0):
    """A freshly created admin/exec role pair can take longer to become assumable by
    CloudFormation than the CreateStackInstances call takes to be accepted, so the per-account
    deployment can come back FAILED on the first attempt even though the API call itself
    succeeded. Retry the actual dependent outcome -- a SUCCEEDED operation -- bounded, clearing
    out any failed instance before recreating it, instead of sleeping blindly beforehand."""
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        create_op = cf.create_stack_instances(StackSetName=ss_name, Accounts=accounts, Regions=regions)
        op = _wait_stack_set_operation(cf, ss_name, create_op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        if op["Status"] == "SUCCEEDED":
            return op
        remaining = deadline - time.monotonic()
        if remaining <= interval_s:
            return op
        try:
            del_op = cf.delete_stack_instances(
                StackSetName=ss_name, Accounts=accounts, Regions=regions, RetainStacks=False
            )
            _wait_stack_set_operation(cf, ss_name, del_op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        except ClientError:
            pass
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0)))
    return op

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec self-managed StackSet role pair; return (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust),
        Tags=[{"Key": "sim2real-behav", "Value": admin_name}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    _create_role_retrying_principal(
        iam, RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust),
        Tags=[{"Key": "sim2real-behav", "Value": exec_name}],
    )
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    return admin["Role"]["Arn"], exec_name

def _teardown_stack_set(cf, name):
    """Delete any instances (wait for the op), then delete the stack set."""
    try:
        summaries = cf.list_stack_instances(StackSetName=name).get("Summaries", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if summaries:
        accounts = sorted({s["Account"] for s in summaries})
        regions = sorted({s["Region"] for s in summaries})
        try:
            op = cf.delete_stack_instances(
                StackSetName=name, Accounts=accounts, Regions=regions, RetainStacks=False
            )
            _wait_stack_set_operation(cf, name, op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStackSet must be rejected while stack instances still exist under it, must not
    remove the StackSet while rejecting, and must succeed on the identical call once the
    instances are gone."""
    cf = ctx.client("cloudformation")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: DeleteStackSet on an *empty* stack set (same roles, same template)
    # succeeds outright. Without this, a target that rejects every DeleteStackSet call would
    # be indistinguishable from one that specifically enforces the non-empty rule below.
    control_name = ctx.unique_name("sim2real-behav-ss-control-")
    cf.create_stack_set(
        StackSetName=control_name,
        TemplateBody=_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-behav", "Value": control_name}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, control_name))
    cf.delete_stack_set(StackSetName=control_name)
    control_gone = _expect_error(lambda: cf.describe_stack_set(StackSetName=control_name))
    expected = ("StackSetNotFoundException", f"StackSet {control_name} not found")
    assert control_gone == expected, (
        f"positive control: expected {expected!r} after deleting an empty stack set, got {control_gone!r}"
    )

    name = ctx.unique_name("sim2real-behav-ss-nonempty-")
    cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-behav", "Value": name}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))

    create_result = _create_stack_instances_with_retry(cf, name, [account], [ctx.region])
    assert create_result["Status"] == "SUCCEEDED", (
        f"setup: stack instance creation did not succeed within the retry budget, "
        f"status={create_result['Status']!r}"
    )

    got = _expect_error(lambda: cf.delete_stack_set(StackSetName=name))
    expected = ("StackSetNotEmptyException", "StackSet is not empty")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Effect-absent: the rejected delete must not have removed the StackSet.
    described = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert described["Status"] == "ACTIVE", (
        f"stack set must remain ACTIVE after a rejected delete, got {described['Status']!r}"
    )

    # Restore: remove the instance, then the identical delete call must now succeed.
    del_op = cf.delete_stack_instances(
        StackSetName=name, Accounts=[account], Regions=[ctx.region], RetainStacks=False
    )
    del_result = _wait_stack_set_operation(cf, name, del_op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
    assert del_result["Status"] == "SUCCEEDED", (
        f"restore: stack instance deletion did not succeed, status={del_result['Status']!r}"
    )

    cf.delete_stack_set(StackSetName=name)
    gone = _expect_error(lambda: cf.describe_stack_set(StackSetName=name))
    expected = ("StackSetNotFoundException", f"StackSet {name} not found")
    assert gone == expected, (
        f"expected the identical delete to succeed once empty: {expected!r}, got {gone!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
