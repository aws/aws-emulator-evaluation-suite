"""stack-set-operation-lifecycle-tracking."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-operation-lifecycle-tracking"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


_ACCEPTED = ("<call accepted>", None)


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised, else
    _ACCEPTED, whose code no error code equals."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _ACCEPTED

def _retry_on_codes(fn, codes, attempts=8, delay_s=5.0):
    """Retry fn() while it raises a ClientError whose code is in codes; re-raise anything else."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") not in codes:
                raise
            time.sleep(delay_s)
    raise last_exc

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

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec self-managed StackSet role pair; return (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    # The admin role's ARN was just created; IAM's cross-role principal validation on CreateRole
    # is itself eventually consistent, so referencing it as a Principal can transiently 400 with
    # MalformedPolicyDocument until that propagates. Retry on the real signal, not a fixed sleep.
    _retry_on_codes(
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust), Tags=_MANAGED_TAGS),
        {"MalformedPolicyDocument"},
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A StackSet operation is queryable through describe/list during and after completion,
    and StopStackSetOperation is only ever accepted while it's still running."""
    cf = ctx.client("cloudformation")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    name = ctx.unique_name("sim2real-behav-ss-op-")
    cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    # StackSets validates that it can assume the exec/admin role pair when the first
    # operation actually runs, not at CreateStackSet time; the roles above may not have
    # finished propagating yet, so retry on the real signal instead of a fixed sleep.
    op = _retry_on_codes(
        lambda: cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region]),
        {"AccessDenied", "ValidationError", "InvalidOperationException"},
    )
    op_id = op["OperationId"]

    # Race a stop against the (likely fast) operation. AWS only ever accepts the stop
    # while the operation is still running, and an accepted stop always lands STOPPED.
    stop_code, stop_msg = _client_error(
        lambda: cf.stop_stack_set_operation(StackSetName=name, OperationId=op_id)
    )
    result = _wait_stack_set_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
    if (stop_code, stop_msg) == _ACCEPTED:
        assert result["Status"] == "STOPPED", result
    else:
        assert stop_code == "InvalidOperationException", stop_code
        assert result["Status"] == "SUCCEEDED", result
        assert stop_msg == "Cannot Stop since Operation is in SUCCEEDED", stop_msg

    described = cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]
    assert described["OperationId"] == op_id
    assert described["Status"] == result["Status"], described

    ops = cf.list_stack_set_operations(StackSetName=name)["Summaries"]
    assert any(o["OperationId"] == op_id for o in ops), ops

    # A stop that wins the race can land STOPPED before any per-instance work item
    # exists, so ListStackSetOperationResults is legitimately empty in that case
    # (confirmed on real AWS: an accepted stop produced zero results). A SUCCEEDED
    # operation must have produced a result for the account/region it targeted.
    results = cf.list_stack_set_operation_results(StackSetName=name, OperationId=op_id)["Summaries"]
    if result["Status"] == "SUCCEEDED":
        assert results, "expected per-account/region operation results for a completed operation"
        assert any(r["Account"] == account and r["Region"] == region for r in results), results
    else:
        assert not any(r["Status"] == "SUCCEEDED" for r in results), results

    # Once terminal, a repeat stop is either rejected outright or accepted as a harmless
    # no-op (confirmed on real AWS: stopping an already-STOPPED operation returns success
    # with no error) -- but the operation's terminal status can never be reverted by it.
    code2, msg2 = _client_error(
        lambda: cf.stop_stack_set_operation(StackSetName=name, OperationId=op_id)
    )
    if (code2, msg2) != _ACCEPTED:
        assert code2 == "InvalidOperationException", code2
        assert msg2 == f"Cannot Stop since Operation is in {result['Status']}", msg2
    final = cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]
    assert final["Status"] == result["Status"], final

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
