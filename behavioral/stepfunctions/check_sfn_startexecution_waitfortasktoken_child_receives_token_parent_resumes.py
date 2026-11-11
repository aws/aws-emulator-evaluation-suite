"""sfn-startexecution-waitfortasktoken-child-receives-token-parent-resumes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-startexecution-waitfortasktoken-child-receives-token-parent-resumes"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _account(ctx):
    return ctx.account


def _create_role(ctx, principal, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfntok-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn, payload=None):
    arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload or {}),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _poll(probe, predicate, *, timeout_s, what, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


_IAM_RACE_MARKERS = ("not authorized to assume", "cannot be assumed")


def _start_until_submitted(ctx, parent_arn, payload=None, *, attempts=6):
    """Start the parent, retrying a fresh execution while a just-created role has not yet
    propagated; return (exec_arn, TaskSubmitted event) once the child has actually been started."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        parent_exec = _start(ctx, parent_arn, payload)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for ev in _history(ctx, parent_exec):
                if ev["type"] == "TaskSubmitted":
                    return parent_exec, ev
            desc = sfn.describe_execution(executionArn=parent_exec)
            if desc["status"] != "RUNNING":
                break
            time.sleep(1.0)
        else:
            raise AssertionError(f"parent {parent_exec} never submitted its child within 30s")
        if desc["status"] != "FAILED" or not any(m in (desc.get("cause") or "") for m in _IAM_RACE_MARKERS):
            raise AssertionError(
                f"parent ended {desc['status']!r} before submitting its child: "
                f"{desc.get('error')!r} {desc.get('cause')!r}")
        time.sleep(5)
    raise AssertionError(f"the parent's role never propagated: {desc!r}")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A states:startExecution.waitForTaskToken Task's TaskSubmitted event carries the child's
    StartExecution response; the child's own input carries that same token, and the parent blocks
    until SendTaskSuccess names it, then resumes with that call's output.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-stepfunctions.html
    """
    sfn = ctx.client("stepfunctions")
    account = _account(ctx)
    child_name = ctx.unique_name("sim2real-behav-tokchild-")
    child_role = _create_role(ctx, "states.amazonaws.com", [])
    child_arn = _create_state_machine(
        ctx, {"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}},
        child_role, name=child_name,
    )

    parent_role = _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "states:StartExecution", "Resource": child_arn},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account}:execution:{child_name}:*"},
    ])
    parent_arn = _create_state_machine(ctx, {
        "StartAt": "StartChild",
        "States": {
            "StartChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.waitForTaskToken",
                "Parameters": {
                    "StateMachineArn": child_arn,
                    "Input": {"token.$": "$$.Task.Token", "job": "sim2real"},
                },
                "TimeoutSeconds": 120,
                "End": True,
            },
        },
    }, parent_role)

    parent_exec, submitted = _start_until_submitted(ctx, parent_arn, {})
    submitted_output = json.loads(submitted["taskSubmittedEventDetails"]["output"])
    assert {"ExecutionArn", "StartDate"} <= submitted_output.keys(), (
        f"TaskSubmitted must carry the child's StartExecution response (ExecutionArn, "
        f"StartDate); got keys {sorted(submitted_output)!r}"
    )
    child_exec = submitted_output["ExecutionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, child_exec))

    child_desc = _poll(lambda: sfn.describe_execution(executionArn=child_exec),
                        lambda d: d.get("input") is not None, timeout_s=30,
                        what="child execution input available")
    child_input = json.loads(child_desc["input"])
    token = child_input.get("token")
    assert isinstance(token, str) and len(token) > 50 and "$$" not in token, (
        f"the child's own input must carry the substituted task token, not a literal path; "
        f"got {str(token)[:120]!r}"
    )
    assert child_input.get("job") == "sim2real", (
        f"the static Input field must be carried verbatim to the child; got {child_input!r}"
    )

    running = sfn.describe_execution(executionArn=parent_exec)
    assert running["status"] == "RUNNING", (
        f"the parent must still be blocked on the token, got {running['status']!r}"
    )

    sfn.send_task_success(taskToken=token, output=json.dumps({"result": "sim2real-done"}))

    final = _poll(lambda: sfn.describe_execution(executionArn=parent_exec),
                  lambda d: d["status"] in _TERMINAL, timeout_s=60, what="parent terminal")
    assert final["status"] == "SUCCEEDED", (
        f"the parent must resume and succeed once SendTaskSuccess names its token, got "
        f"{final['status']!r}: {final.get('error')!r} {final.get('cause')!r}"
    )
    assert json.loads(final["output"]) == {"result": "sim2real-done"}, (
        f"the parent's output must be exactly the SendTaskSuccess payload, got {final.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
