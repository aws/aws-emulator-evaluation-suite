"""stack-set-operation-single-flight-sequencing."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-operation-single-flight-sequencing"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _client_error(fn, what):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises; raise
    AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")

def _wait_role_visible(iam, role_name, timeout_s=60, interval_s=2):
    """Poll GetRole until the freshly created role is visible; IAM reads lag writes briefly."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"IAM role {role_name} never became visible")

def _create_role_with_principal_retry(iam, role_name, trust_policy, tags, timeout_s=240, interval_s=5):
    """create_role() can raise MalformedPolicyDocument ("Invalid principal in policy") for a
    while after GetRole already returns the principal role; retry within a bound for IAM lag."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=tags)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "MalformedPolicyDocument" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=180, interval_s=3):
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

def _wait_condition_template(timeout_seconds=240):
    return json.dumps({
        "Resources": {
            "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Waiter": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {
                    "Handle": {"Ref": "WaitHandle"},
                    "Timeout": str(timeout_seconds),
                    "Count": "1",
                },
            },
        }
    })

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec self-managed StackSet role pair; return (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    tags = [{"Key": "sim2real-check", "Value": CHECK}]
    admin = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=tags
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    _wait_role_visible(iam, admin_name)
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    _create_role_with_principal_retry(iam, exec_name, json.dumps(exec_trust), tags)
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    _wait_inline_policy_visible(iam, admin_name, "AssumeExecRole")
    return admin["Role"]["Arn"], exec_name


def _wait_inline_policy_visible(iam, role_name, policy_name, timeout_s=60, interval_s=3):
    """Poll GetRolePolicy until the just-written inline policy is readable; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second StackSet operation issued while one is RUNNING is rejected with
    OperationInProgressException and never queued; once the first is terminal, the next
    operation is accepted and sequenced after it."""
    cf = ctx.client("cloudformation")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    name = ctx.unique_name("sim2real-behav-ss-flight-")
    stack_set_id = cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_wait_condition_template(30),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackSetId"]
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    op1 = cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region])
    op1_id = op1["OperationId"]

    # Immediately race a second StackSet-level operation while op1 is RUNNING.
    code, msg = _client_error(
        lambda: cf.update_stack_set(
            StackSetName=name,
            UsePreviousTemplate=True,
            Description="second",
            AdministrationRoleARN=admin_arn,
            ExecutionRoleName=exec_name,
        ),
        "UpdateStackSet while op1 is running",
    )
    assert code == "OperationInProgressException", code
    stack_set_arn = f"arn:aws:cloudformation:{region}:{account}:stackset/{stack_set_id}"
    assert msg == f"Another Operation on StackSet {stack_set_arn} is in progress: {op1_id}", msg

    # The rejected call must never have been queued as a real operation.
    ops_during = cf.list_stack_set_operations(StackSetName=name)["Summaries"]
    assert len(ops_during) == 1, (
        f"expected exactly 1 stack set operation while op1 is running, got {len(ops_during)}: {ops_during}"
    )
    assert ops_during[0]["OperationId"] == op1_id, (
        f"the sole listed operation is {ops_during[0]['OperationId']!r}, not the running op1 {op1_id!r}"
    )

    op1_result = _wait_stack_set_operation(cf, name, op1_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=180)
    assert op1_result["Status"] in {"FAILED", "SUCCEEDED"}, op1_result

    described = cf.describe_stack_set_operation(StackSetName=name, OperationId=op1_id)["StackSetOperation"]
    assert described["OperationId"] == op1_id, (
        f"DescribeStackSetOperation returned {described['OperationId']!r}, expected op1 {op1_id!r}"
    )
    assert described["Action"] == "CREATE", (
        f"op1's Action is {described['Action']!r}, expected CREATE (it was a CreateStackInstances)"
    )

    # Now that op1 is terminal, the next operation is accepted -- and
    # sequenced strictly after it (submission order preserved).
    op3 = cf.delete_stack_instances(
        StackSetName=name, Accounts=[account], Regions=[region], RetainStacks=False
    )
    op3_id = op3["OperationId"]
    op3_result = _wait_stack_set_operation(cf, name, op3_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=180)
    assert op3_result["Status"] == "SUCCEEDED", op3_result

    ops_after = cf.list_stack_set_operations(StackSetName=name)["Summaries"]
    by_id = {o["OperationId"]: o for o in ops_after}
    assert {op1_id, op3_id}.issubset(by_id), ops_after
    assert by_id[op3_id]["CreationTimestamp"] >= by_id[op1_id]["CreationTimestamp"], (
        "the second accepted operation must be sequenced after the first",
        ops_after,
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
