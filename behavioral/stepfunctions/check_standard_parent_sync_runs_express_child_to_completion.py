"""standard-parent-sync-runs-express-child-to-completion."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standard-parent-sync-runs-express-child-to-completion"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A STANDARD parent's states:startExecution.sync and .sync:2 tasks each run an
    EXPRESS child to completion and return its result; the child's ExecutionArn uses
    the ':express:' ARN form and carries no RedriveCount/RedriveDate at all."""
    child_name = ctx.unique_name("sim2real-behav-sync-expchild-")
    role_arn = _sync_role(ctx, [child_name])
    child_arn = _create_state_machine(ctx, {
        "Comment": "compute a structured value from the parent-supplied input",
        "StartAt": "Compute",
        "States": {"Compute": {
            "Type": "Pass",
            "Parameters": {"seed.$": "$.seed", "n": 5},
            "End": True,
        }},
    }, role_arn, name=child_name, sm_type="EXPRESS")
    parent_arn = _create_state_machine(ctx, {
        "Comment": "call the EXPRESS child via .sync, then via .sync:2",
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
    expected = {"seed": seed, "n": 5}
    parent = _start_until_terminal(ctx, parent_arn, {"seed": seed}, timeout_s=120)
    assert parent["status"] == "SUCCEEDED", (
        f"the parent ended {parent['status']!r}: {parent.get('error')!r} {parent.get('cause')!r}"
    )

    events = _history(ctx, parent["executionArn"])
    succeeded = {e["taskSucceededEventDetails"]["resource"]: e["taskSucceededEventDetails"]
                 for e in events if e["type"] == "TaskSucceeded"}
    assert set(succeeded) == {"startExecution.sync", "startExecution.sync:2"}, (
        f"TaskSucceeded resources were {sorted(succeeded)!r}"
    )
    v1 = json.loads(succeeded["startExecution.sync"]["output"])
    v2 = json.loads(succeeded["startExecution.sync:2"]["output"])

    assert v1.get("Status") == v2.get("Status") == "SUCCEEDED", (
        f"child Status fields were {v1.get('Status')!r} / {v2.get('Status')!r}"
    )
    assert json.loads(v1["Output"]) == expected, (
        f".sync child Output decodes to {json.loads(v1['Output'])!r}, expected {expected!r}"
    )
    assert v2["Output"] == expected, f".sync:2 child Output was {v2['Output']!r}, expected {expected!r}"

    for label, result in (("sync", v1), ("sync:2", v2)):
        exec_arn = result.get("ExecutionArn")
        assert exec_arn, f".{label} task result carried no ExecutionArn: {result!r}"
        assert ":express:" in exec_arn, (
            f".{label} child ExecutionArn {exec_arn!r} does not use the ':express:' ARN form"
        )
        assert "RedriveCount" not in result, (
            f".{label} task result carries RedriveCount={result.get('RedriveCount')!r}; an "
            f"EXPRESS child must report no redrive fields at all"
        )
        assert "RedriveDate" not in result, (
            f".{label} task result carries RedriveDate={result.get('RedriveDate')!r}; an "
            f"EXPRESS child must report no redrive fields at all"
        )

    assert v1["ExecutionArn"] != v2["ExecutionArn"], (
        f"both tasks reported the same child execution {v1['ExecutionArn']!r}"
    )

    # Positive control: the identical STANDARD child still reports RedriveCount=0, so the
    # absence above is specific to EXPRESS, not a general property of this task result shape.
    standard_child_name = ctx.unique_name("sim2real-behav-sync-stdchild-")
    standard_role_arn = _sync_role(ctx, [standard_child_name])
    standard_child_arn = _create_state_machine(ctx, {
        "Comment": "compute a structured value from the parent-supplied input",
        "StartAt": "Compute",
        "States": {"Compute": {
            "Type": "Pass",
            "Parameters": {"seed.$": "$.seed", "n": 5},
            "End": True,
        }},
    }, standard_role_arn, name=standard_child_name)
    control_parent_arn = _create_state_machine(ctx, {
        "Comment": "call the STANDARD child via .sync",
        "StartAt": "CallChild",
        "States": {"CallChild": {
            "Type": "Task",
            "Resource": "arn:aws:states:::states:startExecution.sync",
            "Parameters": {"StateMachineArn": standard_child_arn, "Input": {"seed.$": "$.seed"}},
            "End": True,
        }},
    }, standard_role_arn)
    control_parent = _start_until_terminal(ctx, control_parent_arn, {"seed": seed}, timeout_s=120)
    assert control_parent["status"] == "SUCCEEDED", (
        f"positive control: the STANDARD-child parent ended {control_parent['status']!r}"
    )
    control_events = _history(ctx, control_parent["executionArn"])
    control_result = json.loads(next(
        e["taskSucceededEventDetails"]["output"]
        for e in control_events if e["type"] == "TaskSucceeded"
    ))
    assert control_result.get("RedriveCount") == 0, (
        f"positive control: the STANDARD child's task result RedriveCount was "
        f"{control_result.get('RedriveCount')!r}, expected 0"
    )
    assert ":express:" not in control_result["ExecutionArn"], (
        f"positive control: the STANDARD child's ExecutionArn unexpectedly used the "
        f"':express:' form: {control_result['ExecutionArn']!r}"
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
        {"Effect": "Allow", "Action": ["states:StartExecution", "states:StartSyncExecution"],
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:stateMachine:{n}"
                      for n in child_names]},
        # Execution-scoped: the STANDARD form (`execution:<name>:*`) and the EXPRESS form
        # (`express:<name>:*`) are different ARN prefixes for the same child name.
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:{kind}:{n}:*"
                      for n in child_names for kind in ("execution", "express")]},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
