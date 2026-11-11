"""log-sfn-sync-nonexistent-child-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-sfn-sync-nonexistent-child-rejected"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_SYNC_RESOURCE = "startExecution.sync:2"


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A .sync:2 task naming a state machine that does not exist fails the parent with
    StepFunctions.StateMachineDoesNotExistException naming that ARN, and never starts a child;
    a sibling parent targeting a real child succeeds, proving the role and mechanism work."""
    role = _role(ctx)
    real_child = _real_child(ctx, role)
    missing_child_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:"
        f"{ctx.unique_name('sim2real-absent-sync-child-')}"[:80]
    )

    ok_parent = _parent(ctx, role, real_child)
    ok_exec = _start(ctx, ok_parent)
    ok_d = _wait_terminal(ctx, ok_exec)
    assert ok_d["status"] == "SUCCEEDED", (
        f"positive control: the parent targeting a real child ended {ok_d['status']!r}: "
        f"{ok_d.get('error')!r} {ok_d.get('cause')!r}")

    bad_parent = _parent(ctx, role, missing_child_arn)
    bad_exec = _start(ctx, bad_parent)
    bad_d = _wait_terminal(ctx, bad_exec)
    assert bad_d["status"] == "FAILED", f"missing-child parent ended {bad_d['status']!r}: {bad_d!r}"
    assert bad_d.get("error") == "StepFunctions.StateMachineDoesNotExistException", (
        f"missing-child parent must fail with StepFunctions.StateMachineDoesNotExistException: "
        f"{bad_d.get('error')!r}, cause {bad_d.get('cause')!r}")
    cause = bad_d.get("cause") or ""
    assert f"State Machine Does Not Exist: '{missing_child_arn}'" in cause, (
        f"cause must name the missing child ARN: {cause!r}")
    code = re.search(r"Error Code: (\w+)", cause)
    assert code and code.group(1) == "StateMachineDoesNotExist", (
        f"cause must embed the service's StateMachineDoesNotExist error code: {cause!r}")

    events = _history(ctx, bad_exec)
    types = [e["type"] for e in events]
    assert "TaskSubmitted" not in types, (
        f"a task naming a nonexistent child must never report a submitted child: {types!r}")
    failed = [e for e in events if e["type"] == "TaskFailed"]
    assert len(failed) == 1 and failed[0]["taskFailedEventDetails"]["resource"] == _SYNC_RESOURCE, (
        f"expected one TaskFailed on {_SYNC_RESOURCE!r}: {failed!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_SYNC_ACTIONS = [
    "states:StartExecution", "states:DescribeExecution", "states:StopExecution",
    "events:PutTargets", "events:PutRule", "events:DescribeRule",
]


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnsyncneg-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn sync nonexistent-child rejection",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="allow",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": _SYNC_ACTIONS, "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="allow"))
    return arn


def _create_with_retry(ctx, **kwargs) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the new role's
    trust propagates (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _real_child(ctx, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfnsyncneg-child-")[:80]
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})
    return _create_with_retry(
        ctx, name=name, definition=definition, roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK[:250]}])


def _parent(ctx, role_arn: str, child_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfnsyncneg-parent-")[:80]
    definition = json.dumps({
        "StartAt": "StartChild",
        "States": {
            "StartChild": {
                "Type": "Task",
                "Resource": f"arn:aws:states:::states:{_SYNC_RESOURCE}",
                "Parameters": {"StateMachineArn": child_arn, "Input": {}},
                "End": True,
            },
        },
    })
    return _create_with_retry(
        ctx, name=name, definition=definition, roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK[:250]}])


def _start(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
    return arn


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 120s: {last!r}")


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
