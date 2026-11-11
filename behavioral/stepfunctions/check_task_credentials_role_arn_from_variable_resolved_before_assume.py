"""task-credentials-role-arn-from-variable-resolved-before-assume."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-role-arn-from-variable-resolved-before-assume"
GROUP = "task_credentials"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Task's `Credentials.RoleArn`, resolved through an intrinsic over a variable, is assumed
    per-execution: an assumable role lets the task run as it, and one the execution role may not
    assume fails States.TaskFailed naming both roles, not a definition-time error.
    """
    exec_role_arn, exec_role_name = _create_sfn_role(ctx)
    assumable_arn, assumable_name = _create_target_role(ctx, trusts=exec_role_arn)
    unassumable_arn, unassumable_name = _create_target_role(ctx, trusts=None)
    _allow_assume(ctx, exec_role_name, assumable_arn)

    definition = {
        "StartAt": "T",
        "States": {"T": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
            "Parameters": {},
            "Credentials": {"RoleArn.$": "States.Format('{}', $.roleArn)"},
            "End": True,
        }},
    }
    sm_arn = _create_state_machine(ctx, definition, exec_role_arn)

    good = _run_until_propagated(ctx, sm_arn, {"roleArn": assumable_arn})
    assert good["status"] == "SUCCEEDED", (
        f"a Credentials.RoleArn resolved from a variable through an intrinsic, naming a role the "
        f"execution role may assume, must succeed; got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    identity = json.loads(good["output"])
    assert identity["Arn"].startswith(f"arn:aws:sts::{ctx.account}:assumed-role/{assumable_name}/"), (
        f"the task must actually run AS the resolved role, not the execution role; got "
        f"identity Arn {identity['Arn']!r}"
    )

    bad = _run_execution(ctx, sm_arn, {"roleArn": unassumable_arn})
    assert bad["status"] == "FAILED", (
        f"a Credentials.RoleArn naming a role the execution role may not assume must fail, got "
        f"{bad['status']!r} output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.TaskFailed", (
        f"expected error 'States.TaskFailed', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == (
        f"The role {exec_role_arn} is not authorized to assume the task state's role, "
        f"{unassumable_arn}."
    ), f"unexpected Credentials rejection cause {bad.get('cause')!r}"


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = (
    "not authorized", "AccessDenied", "cannot be assumed", "security token", "StsException",
)


def _create_sfn_role(ctx):
    """The state machine's own execution role."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfncreds-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn task-credentials execution role",
        Tags=[{"Key": "sim2real", "Value": "sfn-task-credentials"}],
    )["Role"]["Arn"]

    def _delete():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete)
    return arn, role_name


def _create_target_role(ctx, *, trusts):
    """A standalone role: trusting `trusts` (the execution role) when given, else an unrelated
    service principal so the execution role may never assume it."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfncreds-target-")
    principal = {"AWS": trusts} if trusts else {"Service": "ec2.amazonaws.com"}
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    }
    # A just-created execution role is not always immediately usable as a trust-policy
    # principal elsewhere in IAM.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                Description="sim2real-behav sfn task-credentials target role",
                Tags=[{"Key": "sim2real", "Value": "sfn-task-credentials"}],
            )["Role"]["Arn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn, role_name


def _allow_assume(ctx, exec_role_name, target_arn):
    """Grant the execution role permission to call sts:AssumeRole on the assumable target."""
    iam = ctx.client("iam")
    policy_name = f"{exec_role_name}-assume"
    iam.put_role_policy(
        RoleName=exec_role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": target_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=exec_role_name, PolicyName=policy_name))


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfncreds-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-task-credentials"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _run_until_propagated(ctx, sm_arn, payload, *, timeout_s=150.0, max_attempts=6):
    """Retry the assumable-role control while the freshly attached AssumeRole policy and the
    target's trust policy are still propagating through IAM."""
    last = None
    for _ in range(max_attempts):
        last = _run_execution(ctx, sm_arn, payload, timeout_s=timeout_s)
        blob = (last.get("cause") or "") + (last.get("error") or "")
        if last["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return last
        time.sleep(5)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
