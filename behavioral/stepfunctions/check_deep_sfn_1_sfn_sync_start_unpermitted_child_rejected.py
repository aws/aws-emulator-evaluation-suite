"""deep-sfn-1-sfn-sync-start-unpermitted-child-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-1-sfn-sync-start-unpermitted-child-rejected"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A .sync task whose role may start child A but not B fails the parent with a permissions
    error when targeting B, and B never runs; a parent targeting A on the same role succeeds
    first, proving the policy has propagated."""
    sfn = ctx.client("stepfunctions")
    allowed_name = ctx.unique_name("sim2real-behav-sync-child-")
    denied_name = ctx.unique_name("sim2real-behav-sync-child-")
    role_arn = _sync_role(ctx, [allowed_name])
    child_def = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    allowed_arn = _create_state_machine(ctx, child_def, role_arn, name=allowed_name)
    denied_arn = _create_state_machine(ctx, child_def, role_arn, name=denied_name)

    def _parent(child_arn):
        return _create_state_machine(ctx, {
            "StartAt": "CallChild",
            "States": {"CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {"StateMachineArn": child_arn, "Input": {}},
                "End": True,
            }},
        }, role_arn)

    allowed_parent = _parent(allowed_arn)
    denied_parent = _parent(denied_arn)

    ok = _run_to_terminal(ctx, allowed_parent, {})
    assert ok["status"] == "SUCCEEDED", (
        f"positive control: the permitted child's parent ended {ok['status']!r}: "
        f"{ok.get('error')!r} {ok.get('cause')!r}"
    )
    assert len(_executions(ctx, allowed_arn)) == 1, "positive control: child A did not run once"

    # Exactly one attempt: the role is proven effective by the control above.
    arn = _start(ctx, denied_parent, {})
    bad = _poll(lambda: sfn.describe_execution(executionArn=arn),
                lambda d: d["status"] in _TERMINAL, timeout_s=90, what=f"{arn} terminal")
    assert bad["status"] == "FAILED", (
        f"the parent targeting an unpermitted child ended {bad['status']!r}, expected FAILED"
    )
    events = _history(ctx, arn)
    types = [e["type"] for e in events]
    failed = [e for e in events if e["type"] == "TaskFailed"]
    assert len(failed) == 1, f"expected one TaskFailed: {types!r}"
    d = failed[0]["taskFailedEventDetails"]
    assert d.get("error") == "StepFunctions.AWSStepFunctionsException", (
        f"the refused .sync task failed with {d.get('error')!r} (cause {d.get('cause')!r})"
    )
    embedded = re.search(r"Error Code: (\w+)", d.get("cause") or "")
    assert embedded and embedded.group(1) == "AccessDeniedException", (
        f"the Cause does not carry the service's AccessDeniedException: {d.get('cause')!r}"
    )
    assert f"on resource: {denied_arn} " in d["cause"], (
        f"the Cause does not name the unpermitted child {denied_arn!r}: {d['cause']!r}"
    )
    assert "TaskSubmitted" not in types, (
        f"the refused task was recorded as having started a child: {types!r}"
    )
    assert _executions(ctx, denied_arn) == [], (
        f"child B ran although the role may not start it: {_executions(ctx, denied_arn)!r}"
    )


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=150, attempts=6):
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


def _executions(ctx, sm_arn):
    """Every execution of this state machine, paginated."""
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"stateMachineArn": sm_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


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
