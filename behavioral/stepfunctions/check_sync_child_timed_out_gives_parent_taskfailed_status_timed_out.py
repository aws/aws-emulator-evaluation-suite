"""sync-child-timed-out-gives-parent-taskfailed-status-timed-out."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-child-timed-out-gives-parent-taskfailed-status-timed-out"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_CHILD_TIMEOUT_S = 8
_CHILD_WAIT_S = 120


@tags("axis:happy-path", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A child that hits its own top-level TimeoutSeconds and ends TIMED_OUT fails the
    parent's startExecution.sync / .sync:2 task as States.TaskFailed, whose Cause names
    the child's Status: TIMED_OUT — for both task-result representations."""
    sfn = ctx.client("stepfunctions")
    child_name = ctx.unique_name("sim2real-behav-sync-tochild-")
    role_arn = _sync_role(ctx, [child_name])
    child_arn = _create_state_machine(ctx, {
        "Comment": "a child whose own execution-level timeout fires before its long Wait",
        "StartAt": "Hold",
        "TimeoutSeconds": _CHILD_TIMEOUT_S,
        "States": {"Hold": {"Type": "Wait", "Seconds": _CHILD_WAIT_S, "End": True}},
    }, role_arn, name=child_name)

    for label, resource in (("sync", "startExecution.sync"), ("sync:2", "startExecution.sync:2")):
        parent_arn = _create_state_machine(ctx, {
            "Comment": "block on a child that will time out",
            "StartAt": "CallChild",
            "States": {"CallChild": {
                "Type": "Task",
                "Resource": f"arn:aws:states:::states:{resource}",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"from": "parent"}},
                "End": True,
            }},
        }, role_arn)

        parent, child = _start_parent_until_child(ctx, parent_arn)
        parent_desc = _poll(lambda: sfn.describe_execution(executionArn=parent),
                            lambda d: d["status"] in _TERMINAL,
                            timeout_s=_CHILD_TIMEOUT_S + 90,
                            what=f".{label} parent {parent} terminal")
        child_desc = sfn.describe_execution(executionArn=child)
        assert child_desc["status"] == "TIMED_OUT", (
            f".{label} child ended {child_desc['status']!r}, expected TIMED_OUT: "
            f"{child_desc.get('error')!r} {child_desc.get('cause')!r}"
        )
        assert parent_desc["status"] == "FAILED", (
            f".{label} parent ended {parent_desc['status']!r}, expected FAILED when its "
            f"child timed out: {parent_desc.get('error')!r} {parent_desc.get('cause')!r}"
        )

        events = _history(ctx, parent)
        task_failed = [e for e in events if e["type"] == "TaskFailed"]
        assert len(task_failed) == 1, (
            f".{label}: expected exactly one TaskFailed, got {len(task_failed)}: "
            f"{[e['type'] for e in events]!r}"
        )
        d = task_failed[0]["taskFailedEventDetails"]
        assert d.get("resourceType") == "states" and d.get("resource") == resource, (
            f".{label} TaskFailed named resource {d.get('resourceType')!r}/{d.get('resource')!r}"
        )
        assert d.get("error") == "States.TaskFailed", (
            f".{label} parent's TaskFailed error was {d.get('error')!r}, expected "
            f"States.TaskFailed"
        )
        cause = json.loads(d.get("cause") or "{}")
        assert cause.get("Status") == "TIMED_OUT", (
            f".{label} TaskFailed Cause was {cause!r}, expected Status=TIMED_OUT"
        )
        assert cause.get("ExecutionArn") == child, (
            f".{label} TaskFailed Cause does not name the child execution {child!r}: {cause!r}"
        )

    # Positive control, in the same file: an identical child with a generous timeout over a
    # short Wait succeeds, proving the FAILED/TIMED_OUT pair above is the timeout, not a
    # setup mistake.
    control_child_name = ctx.unique_name("sim2real-behav-sync-tochild-ctrl-")
    control_role_arn = _sync_role(ctx, [control_child_name])
    control_child_arn = _create_state_machine(ctx, {
        "Comment": "a child whose Wait finishes well inside its own timeout",
        "StartAt": "Hold",
        "TimeoutSeconds": 900,
        "States": {"Hold": {"Type": "Wait", "Seconds": 2, "End": True}},
    }, control_role_arn, name=control_child_name)
    control_parent_arn = _create_state_machine(ctx, {
        "Comment": "block on a child that finishes well inside its timeout",
        "StartAt": "CallChild",
        "States": {"CallChild": {
            "Type": "Task",
            "Resource": "arn:aws:states:::states:startExecution.sync",
            "Parameters": {"StateMachineArn": control_child_arn, "Input": {"from": "parent"}},
            "End": True,
        }},
    }, control_role_arn)
    control_parent = _start_until_terminal(ctx, control_parent_arn, {}, timeout_s=120)
    assert control_parent["status"] == "SUCCEEDED", (
        f"positive control: the parent ended {control_parent['status']!r}, expected "
        f"SUCCEEDED when its child finishes inside its own timeout: "
        f"{control_parent.get('error')!r} {control_parent.get('cause')!r}"
    )


def _start_until_terminal(ctx, sm_arn, payload, *, timeout_s, attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        arn = _start(ctx, sm_arn, payload)
        desc = _poll(lambda: sfn.describe_execution(executionArn=arn),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {arn} terminal")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


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
    return ctx.account


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
    # (_create_state_machine, _start_until_terminal) absorb it.
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
