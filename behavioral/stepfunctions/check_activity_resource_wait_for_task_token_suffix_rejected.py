"""activity-resource-wait-for-task-token-suffix-rejected."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-resource-wait-for-task-token-suffix-rejected"
GROUP = 'activities'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An Activity Task with the ".waitForTaskToken" suffix fails at runtime with States.Runtime
    ($$.Task.Token does not exist) and is never scheduled; the same Activity without the suffix
    still delivers a task to a worker.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-activities.html
    """
    # Activities are their own callback pattern (GetActivityTask hands out the token), so the
    # suffix is accepted at CreateStateMachine but there is no context-object token to inject.
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx)

    bad_definition = {
        "StartAt": "PauseAndWait",
        "States": {
            "PauseAndWait": {
                "Type": "Task",
                "Resource": activity_arn + ".waitForTaskToken",
                "Parameters": {"token.$": "$$.Task.Token", "payload.$": "$.data"},
                "End": True,
            }
        },
    }
    bad_sm_arn = _create_state_machine(ctx, bad_definition)
    bad_exec_arn = _run_to_terminal_arn(ctx, bad_sm_arn, {"data": "hello"})
    bad_result = sfn.describe_execution(executionArn=bad_exec_arn)

    assert bad_result["status"] == "FAILED", (
        f"expected the .waitForTaskToken-suffixed Activity Task to FAIL, got "
        f"{bad_result['status']!r}: {bad_result.get('cause')!r}"
    )
    assert bad_result.get("error") == "States.Runtime", (
        f"expected error States.Runtime, got {bad_result.get('error')!r}: "
        f"{bad_result.get('cause')!r}"
    )
    cause = bad_result.get("cause") or ""
    assert "$$.Task.Token" in cause and "could not be found" in cause, (
        f"expected the cause to name the missing $$.Task.Token context field, got {cause!r}"
    )

    event_types = _history_types(ctx, bad_exec_arn)
    assert "ActivityScheduled" not in event_types, (
        f"the Activity was scheduled a task despite the failed Parameters evaluation: "
        f"{event_types!r}"
    )

    good_definition = {
        "StartAt": "DoWork",
        "States": {"DoWork": {"Type": "Task", "Resource": activity_arn, "End": True}},
    }
    good_sm_arn = _create_state_machine(ctx, good_definition)
    good_exec_arn = _start_execution(ctx, good_sm_arn, {"job": "process"})

    holder: dict[str, Any] = {}

    def worker() -> None:
        try:
            task = _poll_activity_task(ctx, activity_arn, timeout_s=65)
            token = task.get("taskToken")
            holder["token"] = token
            if token:
                sfn.send_task_success(taskToken=token, output=json.dumps({"result": "done"}))
        except Exception as exc:  # surfaced via holder for the main thread to assert
            holder["error"] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(90)

    assert "error" not in holder, f"positive-control worker failed: {holder.get('error')}"
    assert holder.get("token"), "the positive control never received a task token"

    good_result = _wait_terminal(ctx, good_exec_arn, timeout_s=60)
    assert good_result["status"] == "SUCCEEDED", (
        f"the positive control execution was {good_result['status']!r}: "
        f"{good_result.get('cause')!r}"
    )
    good_output = json.loads(good_result["output"])
    assert good_output == {"result": "done"}, (
        f"expected the positive control's output to be the worker's reply, got {good_output!r}"
    )


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDeniedException",
)


_SFN_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _execution_role(ctx):
    """An execution role created once per run; an Activity task needs no permission of the role,
    so it carries only the Step Functions trust."""
    cached = getattr(ctx, "_sim2real_sfn_role", None)
    if cached:
        return cached
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_SFN_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx._sim2real_sfn_role = arn
    return arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    role_arn = _execution_role(ctx)
    # A role created seconds ago is refused (AccessDeniedException) until IAM propagates it to
    # Step Functions; bounded, and only that refusal is retried.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_data):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal_arn(ctx, sm_arn, input_data, *, timeout_s=60, attempts=6):
    """Start an execution and return its ARN once terminal, retrying with a fresh execution
    while the role's first runtime use still fails on IAM propagation."""
    desc = None
    exec_arn = None
    for _ in range(attempts):
        exec_arn = _start_execution(ctx, sm_arn, input_data)
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return exec_arn
        time.sleep(5)
    return exec_arn


def _history_types(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(e["type"] for e in resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    """GetActivityTask long-polls up to ~60s server-side; retry the call if it comes back empty."""
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
