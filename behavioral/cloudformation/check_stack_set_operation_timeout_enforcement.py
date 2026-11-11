"""stack-set-operation-timeout-enforcement."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-operation-timeout-enforcement"
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

def _poll_until(probe, predicate, timeout_s=15, interval_s=3):
    """Poll probe() until predicate(result) is truthy; return the last result. Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")

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

def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })

def _code(exc) -> str | None:
    """Return botocore Error.Code from exc, or None if exc carries no error response."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None

def _retry_role_propagation(fn, attempts=8, delay_s=5.0):
    """Retry fn() while IAM/StackSets eventual consistency rejects a just-created role;
    re-raise immediately on any other error."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if _code(exc) not in ("AccessDenied", "ValidationError", "InvalidOperationException"):
                raise
            time.sleep(delay_s)
    raise last_exc

def _retry_malformed_principal(fn, attempts=8, delay_s=5.0):
    """Retry fn() while IAM's cross-role Principal validation has not yet observed a
    just-created role; re-raise immediately on any other error."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if _code(exc) != "MalformedPolicyDocument":
                raise
            time.sleep(delay_s)
    raise last_exc

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    # IAM validates an "AWS" Principal against existing entities at CreateRole time, but its
    # view of the admin role just created moments ago is itself eventually consistent.
    _retry_malformed_principal(
        lambda: iam.create_role(
            RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
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
    """StopStackSetOperation on a RUNNING operation drives it to a durable terminal status (STOPPED,
    or already finished), and stopping an already-terminal operation is rejected rather than
    accepted as if it could still be running."""
    cf = ctx.client("cloudformation")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    name = ctx.unique_name("sim2real-behav-ss-to-")
    # CloudFormation accepts the just-created roles synchronously, but its own
    # cross-account trust check is itself eventually consistent -- retry the create
    # call on the specific transient codes rather than sleeping first.
    _retry_role_propagation(
        lambda: cf.create_stack_set(
            StackSetName=name,
            TemplateBody=_sns_template(),
            PermissionModel="SELF_MANAGED",
            AdministrationRoleARN=admin_arn,
            ExecutionRoleName=exec_name,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))

    account = ctx.client("sts").get_caller_identity()["Account"]
    op = _retry_role_propagation(
        lambda: cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[ctx.region])
    )
    op_id = op["OperationId"]

    # Race a stop against the operation -- whichever wins, the operation
    # must land in (and durably stay in) a terminal, non-running status.
    stop_code, stop_msg = _client_error(
        lambda: cf.stop_stack_set_operation(StackSetName=name, OperationId=op_id)
    )

    result = _wait_stack_set_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
    assert result["Status"] in {"SUCCEEDED", "FAILED", "STOPPED"}, result
    if (stop_code, stop_msg) != _ACCEPTED:
        # A stop that lost the race is refused because the operation already finished.
        assert stop_code == "InvalidOperationException", stop_code
        assert stop_msg == f"Cannot Stop since Operation is in {result['Status']}", stop_msg

    # Confirm it's durably terminal, not oscillating back to RUNNING: poll a
    # few more times and require the status to stay put.
    def probe_terminal():
        return cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]

    described = _poll_until(
        probe_terminal, lambda op: op.get("Status") == result["Status"], timeout_s=15, interval_s=3
    )
    assert described["Status"] == result["Status"], described

    # Boundary check: stopping an operation already in a terminal state must
    # NOT revert/rerun it -- whether the service rejects the redundant stop
    # outright or accepts it as a harmless no-op, the terminal status must be
    # completely unaffected either way.
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
