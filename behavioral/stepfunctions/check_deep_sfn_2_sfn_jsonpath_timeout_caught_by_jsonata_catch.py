"""deep-sfn-2-sfn-jsonpath-timeout-caught-by-jsonata-catch."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-sfn-2-sfn-jsonpath-timeout-caught-by-jsonata-catch"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]

_TIMEOUT_SECONDS = 5


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A throwaway execution role: the only integration is an activity, which needs no IAM grant."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mqt-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-mqt: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "mqt"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-mqt-activity-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": "mqt"}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-mqt-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "mqt"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _definition(activity_arn):
    """Top machine JSONPath (the default); the Parallel overrides itself to JSONata so its own
    Catch is JSONata, while the branch Task has no state-level override and so falls back to the
    TOP-LEVEL language (JSONPath) rather than inheriting its parent Parallel's JSONata."""
    return {
        "StartAt": "Wrapper",
        "States": {
            "Wrapper": {
                "Type": "Parallel",
                "QueryLanguage": "JSONata",
                "Branches": [
                    {
                        "StartAt": "JsonPathTask",
                        "States": {
                            "JsonPathTask": {
                                "Type": "Task",
                                "Resource": activity_arn,
                                "TimeoutSeconds": _TIMEOUT_SECONDS,
                                "End": True,
                            }
                        },
                    }
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "Output": {
                            "caught": True,
                            "error": "{% $states.errorOutput.Error %}",
                            "cause": "{% $states.errorOutput.Cause %}",
                        },
                        "Next": "Check",
                    },
                ],
                "Output": {"caught": False, "result": "{% $states.result %}"},
                "Next": "Done",
            },
            "Check": {"Type": "Pass", "End": True},
            "Done": {"Type": "Pass", "End": True},
        },
    }


def _start(ctx, sm_arn, input_data):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-mqt-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _claim_task(ctx, activity_arn, worker_name, *, timeout_s=20):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = sfn.get_activity_task(activityArn=activity_arn, workerName=worker_name)
        if task.get("taskToken"):
            return task["taskToken"]
    raise AssertionError(f"no task claimed from {activity_arn!r} within {timeout_s}s")


def _wait_terminal(ctx, exec_arn, *, timeout_s):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {desc!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Parallel overridden to JSONata catches, via its own JSONata Catch, the States.Timeout a
    plain JSONPath Task inside its branch raises when its TimeoutSeconds elapses unanswered; the
    success path still reaches the Parallel's own Output."""
    role_arn = _execution_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, _definition(activity_arn), role_arn)

    # --- Positive control: a worker claims and completes the task before TimeoutSeconds ----
    control_exec = _start(ctx, sm_arn, {"x": 1})
    control_token = _claim_task(ctx, activity_arn, "sim2real-mqt-worker-control")
    ctx.client("stepfunctions").send_task_success(
        taskToken=control_token, output=json.dumps({"done": True})
    )
    control = _wait_terminal(ctx, control_exec, timeout_s=30)
    assert control["status"] == "SUCCEEDED", (
        f"the positive control must succeed; got {control['status']!r} "
        f"error={control.get('error')!r} cause={control.get('cause')!r}"
    )
    assert _output(control) == {"caught": False, "result": [{"done": True}]}, (
        f"the Parallel's own Output must carry the branch's result array through, got "
        f"{_output(control)!r}"
    )

    # --- The subject: a worker claims the task but never replies; TimeoutSeconds elapses ----
    timeout_exec = _start(ctx, sm_arn, {"x": 2})
    _claim_task(ctx, activity_arn, "sim2real-mqt-worker-timeout")
    timeout = _wait_terminal(ctx, timeout_exec, timeout_s=_TIMEOUT_SECONDS + 30)
    assert timeout["status"] == "SUCCEEDED", (
        f"the Parallel's own JSONata Catch must turn the inner States.Timeout into a caught "
        f"success; got {timeout['status']!r} error={timeout.get('error')!r} "
        f"cause={timeout.get('cause')!r}"
    )
    out = _output(timeout)
    assert out is not None and out.get("caught") is True, (
        f"the JSONata Catch must have run, got output {out!r}"
    )
    assert out.get("error") == "States.Timeout", (
        f"the caught error must be the Task's own States.Timeout, got {out.get('error')!r}"
    )
    assert out.get("cause") == "", (
        f"a Task-level TimeoutSeconds expiry on an activity leaves Cause empty; got "
        f"{out.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
