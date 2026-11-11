"""deep-sfn-1-sfn-sync-parent-stop-aborts-running-child."""
from __future__ import annotations

import json
import time
from datetime import timedelta

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-1-sfn-sync-parent-stop-aborts-running-child"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']

_CHILD_WAIT_S = 60


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """StopExecution on a parent blocked in states:startExecution.sync aborts its RUNNING child
    well before the child's own Wait ends, while an unstopped twin parent's child stays RUNNING
    (the control proving the stop propagated)."""
    sfn = ctx.client("stepfunctions")
    child_name = ctx.unique_name("sim2real-behav-sync-child-")
    role_arn = _sync_role(ctx, [child_name])
    child_arn = _create_state_machine(ctx, {
        "Comment": "a child that only waits",
        "StartAt": "Hold",
        "States": {"Hold": {"Type": "Wait", "Seconds": _CHILD_WAIT_S, "End": True}},
    }, role_arn, name=child_name)
    parent_arn = _create_state_machine(ctx, {
        "Comment": "block on the child via .sync",
        "StartAt": "CallChild",
        "States": {
            "CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"from": "parent"}},
                "End": True,
            }
        },
    }, role_arn)

    stopped_parent, stopped_child = _start_parent_until_child(ctx, parent_arn)
    twin_parent, twin_child = _start_parent_until_child(ctx, parent_arn)
    assert stopped_child != twin_child, (
        f"both parents reported the same child execution {stopped_child!r}"
    )
    for child in (stopped_child, twin_child):
        _poll(lambda c=child: sfn.describe_execution(executionArn=c)["status"],
              lambda s: s == "RUNNING", timeout_s=30, what=f"child {child} RUNNING")

    stop_resp = sfn.stop_execution(
        executionArn=stopped_parent, error="SimStop", cause="stop the parent only")
    parent_stop = stop_resp["stopDate"]

    child_desc = _poll(lambda: sfn.describe_execution(executionArn=stopped_child),
                       lambda d: d["status"] != "RUNNING", timeout_s=50,
                       what=f"child {stopped_child} leaving RUNNING after its parent stopped")
    # The twin is read immediately after: it shares the stopped child's timeline exactly, so
    # if its Wait had run out the stopped child's would have too.
    twin_status = sfn.describe_execution(executionArn=twin_child)["status"]
    twin_parent_status = sfn.describe_execution(executionArn=twin_parent)["status"]

    assert child_desc["status"] == "ABORTED", (
        f"the stopped parent's child ended {child_desc['status']!r}, expected ABORTED: "
        f"{child_desc.get('error')!r} {child_desc.get('cause')!r}"
    )
    lag = child_desc["stopDate"] - parent_stop
    assert timedelta(seconds=-1) <= lag <= timedelta(seconds=45), (
        f"child stopped {lag.total_seconds()!r}s relative to the parent's stopDate "
        f"{parent_stop!r}; expected after the parent stop and within 45 s"
    )
    ran = child_desc["stopDate"] - child_desc["startDate"]
    assert ran < timedelta(seconds=_CHILD_WAIT_S), (
        f"the child ran {ran.total_seconds()!r}s — as long as its own {_CHILD_WAIT_S}s Wait, so "
        f"the stop did not cut it short"
    )
    assert twin_status == "RUNNING", (
        f"the twin child (parent never stopped) was {twin_status!r} when the stopped parent's "
        f"child was ABORTED; expected RUNNING"
    )
    assert twin_parent_status == "RUNNING", (
        f"the never-stopped twin parent was {twin_parent_status!r}, expected RUNNING"
    )

    child_events = _history(ctx, stopped_child)
    child_types = [e["type"] for e in child_events]
    assert child_types[-1] == "ExecutionAborted", (
        f"the aborted child's history ends {child_types[-3:]!r}, expected ExecutionAborted"
    )
    assert "WaitStateExited" not in child_types, (
        f"the aborted child's Wait completed anyway: {child_types!r}"
    )
    parent_types = [e["type"] for e in _history(ctx, stopped_parent)]
    assert parent_types[-1] == "ExecutionAborted", (
        f"the stopped parent's history ends {parent_types[-3:]!r}, expected ExecutionAborted"
    )
    assert "TaskSucceeded" not in parent_types and "TaskFailed" not in parent_types, (
        f"the stopped parent's .sync task closed with a result: {parent_types!r}"
    )
    twin_types = [e["type"] for e in _history(ctx, twin_child)]
    assert "ExecutionAborted" not in twin_types, (
        f"the twin child carries an ExecutionAborted event though its parent was never "
        f"stopped: {twin_types!r}"
    )
    # Only now: stop the twin ourselves (its cleanup is also registered).
    sfn.stop_execution(executionArn=twin_parent, error="SimCleanup", cause="control twin")
    sfn.stop_execution(executionArn=twin_child, error="SimCleanup", cause="control twin")


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "States.Permissions",
    "AccessDeniedException",
)


def _account(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, principal, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnsync-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn sync execution role",
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
    # IAM propagation exposes no condition to poll; the bounded retries at first use
    # (_create_state_machine, _start_parent_until_child) absorb it.
    return role_arn


def _sync_role(ctx, child_names):
    account = _account(ctx)
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:stateMachine:{n}"
                      for n in child_names]},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:execution:{n}:*"
                      for n in child_names]},
        {"Effect": "Allow", "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": f"arn:aws:events:{ctx.region}:{account}:rule/"
                     "StepFunctionsGetEventsForStepFunctionsExecutionRule"},
    ])


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sync-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
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
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn, payload=None):
    arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload or {}),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


def _poll(probe, predicate, *, timeout_s, what, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _start_parent_until_child(ctx, parent_arn, payload=None, *, attempts=6):
    """Start the parent and return (parent, child) once its .sync task has started the child.

    The .sync task is the first runtime use of the role, so an unpropagated policy fails the
    parent with a permissions error; that — and only that — earns a fresh attempt.
    """
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        parent = _start(ctx, parent_arn, payload)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for ev in _history(ctx, parent):
                if ev["type"] == "TaskSubmitted":
                    child = json.loads(ev["taskSubmittedEventDetails"]["output"])["ExecutionArn"]
                    ctx.on_cleanup(lambda a=child: _best_effort_stop(ctx, a))
                    return parent, child
            desc = sfn.describe_execution(executionArn=parent)
            if desc["status"] in _TERMINAL:
                break
            time.sleep(1.0)
        else:
            raise AssertionError(f"parent {parent} never submitted its child within 60s")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            raise AssertionError(
                f"parent ended {desc['status']!r} before starting its child: "
                f"{desc.get('error')!r} {desc.get('cause')!r}")
        time.sleep(5)
    raise AssertionError(f"the parent's role never propagated: {desc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
