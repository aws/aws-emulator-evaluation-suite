"""sync-task-output-is-full-describeexecution-shape."""
from __future__ import annotations

import json
import time
from datetime import timedelta

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-task-output-is-full-describeexecution-shape"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A states:startExecution.sync TaskSucceeded output is the child's complete
    DescribeExecution — Name, StateMachineArn, dates within the parent's window,
    inputDetails/outputDetails.included and RedriveCount=0/RedriveDate=null — not just Output."""
    sfn = ctx.client("stepfunctions")
    child_name = ctx.unique_name("sim2real-behav-sync-child-")
    role_arn = _sync_role(ctx, [child_name])
    child_arn = _create_state_machine(ctx, {
        "Comment": "compute a structured value from the parent-supplied input",
        "StartAt": "Compute",
        "States": {"Compute": {
            "Type": "Pass",
            "Parameters": {"seed.$": "$.seed", "n": 7},
            "End": True,
        }},
    }, role_arn, name=child_name)
    parent_arn = _create_state_machine(ctx, {
        "Comment": "block on the child via .sync and keep its raw task result",
        "StartAt": "CallChild",
        "States": {
            "CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"seed.$": "$.seed"}},
                "End": True,
            }
        },
    }, role_arn)

    seed = ctx.unique_name("seed-")
    parent = _start_until_terminal(ctx, parent_arn, {"seed": seed}, timeout_s=120)
    assert parent["status"] == "SUCCEEDED", (
        f"the parent ended {parent['status']!r}: {parent.get('error')!r} {parent.get('cause')!r}"
    )

    events = _history(ctx, parent["executionArn"])
    succeeded = [e for e in events if e["type"] == "TaskSucceeded"]
    assert len(succeeded) == 1, f"expected exactly one TaskSucceeded, got {len(succeeded)}"
    task_result = json.loads(succeeded[0]["taskSucceededEventDetails"]["output"])

    child_arn_from_task = task_result.get("ExecutionArn")
    assert child_arn_from_task, f"the task result carried no ExecutionArn: {task_result!r}"
    child = sfn.describe_execution(executionArn=child_arn_from_task)
    assert child["status"] == "SUCCEEDED", f"the child ended {child['status']!r}"

    # Every field the task result reports is cross-checked against an independent
    # DescribeExecution of the same child, not merely present.
    assert task_result.get("Name") == child["name"], (
        f"task result Name={task_result.get('Name')!r} != child name={child['name']!r}"
    )
    assert task_result.get("StateMachineArn") == child_arn, (
        f"task result StateMachineArn={task_result.get('StateMachineArn')!r} != {child_arn!r}"
    )
    assert task_result.get("Status") == "SUCCEEDED", (
        f"task result Status={task_result.get('Status')!r}, expected SUCCEEDED"
    )

    assert isinstance(task_result.get("Input"), str), (
        f"Input was {type(task_result.get('Input')).__name__}, expected a JSON string"
    )
    assert json.loads(task_result["Input"]) == json.loads(child["input"]), (
        f"task result Input decodes to {json.loads(task_result['Input'])!r}, "
        f"child input is {json.loads(child['input'])!r}"
    )
    assert task_result.get("InputDetails", {}).get("Included") is True, (
        f"InputDetails was {task_result.get('InputDetails')!r}, expected Included=True"
    )

    assert isinstance(task_result.get("Output"), str), (
        f"Output was {type(task_result.get('Output')).__name__}, expected a JSON string"
    )
    assert json.loads(task_result["Output"]) == json.loads(child["output"]), (
        f"task result Output decodes to {json.loads(task_result['Output'])!r}, "
        f"child output is {json.loads(child['output'])!r}"
    )
    assert task_result.get("OutputDetails", {}).get("Included") is True, (
        f"OutputDetails was {task_result.get('OutputDetails')!r}, expected Included=True"
    )

    assert task_result.get("RedriveCount") == 0, (
        f"task result RedriveCount={task_result.get('RedriveCount')!r}, expected 0 for a "
        f"STANDARD child that was never redriven"
    )
    assert task_result.get("RedriveDate") is None, (
        f"task result RedriveDate={task_result.get('RedriveDate')!r}, expected null/absent"
    )
    assert child.get("redriveCount") == 0 and child.get("redriveDate") is None, (
        f"the independently-read child DescribeExecution disagrees: redriveCount="
        f"{child.get('redriveCount')!r} redriveDate={child.get('redriveDate')!r}"
    )

    start_date = _as_datetime(task_result.get("StartDate"))
    stop_date = _as_datetime(task_result.get("StopDate"))
    assert start_date is not None and stop_date is not None, (
        f"StartDate={task_result.get('StartDate')!r} StopDate={task_result.get('StopDate')!r}"
    )
    assert parent["startDate"] <= start_date, (
        f"child StartDate {start_date!r} is before the parent even started "
        f"{parent['startDate']!r}"
    )
    assert stop_date <= parent["stopDate"], (
        f"child StopDate {stop_date!r} is after the parent's own StopDate {parent['stopDate']!r}"
    )
    assert start_date <= stop_date, f"child StartDate {start_date!r} is after StopDate {stop_date!r}"


def _as_datetime(value):
    """StartDate/StopDate in the task result are epoch milliseconds per the AWS API."""
    if value is None:
        return None
    from datetime import datetime, timezone
    whole_s, ms = divmod(int(value), 1000)
    return datetime.fromtimestamp(whole_s, tz=timezone.utc) + timedelta(milliseconds=ms)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
