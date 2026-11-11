"""deep-sfn-1-sfn-sync-v1-output-string-vs-v2-output-object."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-1-sfn-sync-v1-output-string-vs-v2-output-object"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """states:startExecution.sync returns the child's Output as a JSON string, .sync:2 as a
    parsed object: one parent calls the same child both ways and the two TaskSucceeded events
    decode to the same value."""
    child_name = ctx.unique_name("sim2real-behav-sync-child-")
    role_arn = _sync_role(ctx, [child_name])
    child_arn = _create_state_machine(ctx, {
        "Comment": "compute a structured value from the parent-supplied input",
        "StartAt": "Compute",
        "States": {"Compute": {
            "Type": "Pass",
            "Parameters": {"seed.$": "$.seed", "n": 3, "nested": {"flag": True, "list": [1, 2]}},
            "End": True,
        }},
    }, role_arn, name=child_name)
    parent_arn = _create_state_machine(ctx, {
        "Comment": "call the child via .sync, then via .sync:2",
        "StartAt": "V1",
        "States": {
            "V1": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"seed.$": "$.seed"}},
                "ResultPath": "$.v1",
                "Next": "V2",
            },
            "V2": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"seed.$": "$.seed"}},
                "ResultPath": "$.v2",
                "End": True,
            },
        },
    }, role_arn)

    seed = ctx.unique_name("seed-")
    expected = {"seed": seed, "n": 3, "nested": {"flag": True, "list": [1, 2]}}
    desc = _run_to_terminal(ctx, parent_arn, {"seed": seed})
    assert desc["status"] == "SUCCEEDED", (
        f"the parent ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )

    events = _history(ctx, desc["executionArn"])
    succeeded = {e["taskSucceededEventDetails"]["resource"]: e["taskSucceededEventDetails"]
                 for e in events if e["type"] == "TaskSucceeded"}
    assert set(succeeded) == {"startExecution.sync", "startExecution.sync:2"}, (
        f"TaskSucceeded resources were {sorted(succeeded)!r}"
    )
    v1 = json.loads(succeeded["startExecution.sync"]["output"])
    v2 = json.loads(succeeded["startExecution.sync:2"]["output"])

    assert isinstance(v1.get("Output"), str), (
        f".sync returned Output as {type(v1.get('Output')).__name__}: {v1.get('Output')!r}; "
        f"expected a JSON string"
    )
    assert json.loads(v1["Output"]) == expected, (
        f".sync Output decodes to {json.loads(v1['Output'])!r}, expected {expected!r}"
    )
    assert isinstance(v2.get("Output"), dict), (
        f".sync:2 returned Output as {type(v2.get('Output')).__name__}: {v2.get('Output')!r}; "
        f"expected an already-parsed object"
    )
    assert v2["Output"] == expected, f".sync:2 Output was {v2['Output']!r}, expected {expected!r}"
    assert isinstance(v1.get("Input"), str) and isinstance(v2.get("Input"), dict), (
        f"Input representation: .sync {type(v1.get('Input')).__name__}, "
        f".sync:2 {type(v2.get('Input')).__name__}"
    )
    assert v1.get("Status") == v2.get("Status") == "SUCCEEDED", (
        f"child Status fields were {v1.get('Status')!r} / {v2.get('Status')!r}"
    )
    assert v1.get("ExecutionArn") != v2.get("ExecutionArn"), (
        f"both tasks reported the same child execution {v1.get('ExecutionArn')!r}"
    )

    final = json.loads(desc["output"])
    assert isinstance(final["v1"]["Output"], str) and final["v2"]["Output"] == expected, (
        f"the parent's own output kept {final!r}"
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
