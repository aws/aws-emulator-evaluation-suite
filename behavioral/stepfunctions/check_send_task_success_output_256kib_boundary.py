"""send-task-success-output-256kib-boundary."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-output-256kib-boundary"
GROUP = 'activities'
SERVICES = ['stepfunctions']

_LIMIT = 256 * 1024
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """SendTaskSuccess with output of exactly the 262144-byte limit is accepted and becomes the
    execution's output; 1024 bytes over is rejected with the same ValidationException StartExecution
    uses for an oversized input, and leaves the task outstanding.
    """
    sfn = ctx.client("stepfunctions")
    act_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    definition = {
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act_arn, "TimeoutSeconds": 300, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Positive control: output of exactly the limit is accepted and arrives intact.
    exact_output = _payload(_LIMIT)
    assert len(exact_output.encode()) == _LIMIT, (
        f"the payload builder is wrong: {len(exact_output.encode())!r} bytes"
    )
    exec_arn = _start_execution(ctx, sm_arn)
    task_token = _poll_activity_task(ctx, act_arn)
    sfn.send_task_success(taskToken=task_token, output=exact_output)
    final = _poll_execution_terminal(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"an exactly {_LIMIT!r}-byte SendTaskSuccess output ended {final['status']!r}: "
        f"{final.get('error')!r} {final.get('cause')!r}"
    )
    assert len(final["output"].encode()) == _LIMIT, (
        f'the execution output is {len(final["output"].encode())!r} bytes, expected exactly {_LIMIT!r}'
    )
    assert final["output"] == exact_output, "the execution output did not arrive intact"

    # Negative: 1024 bytes over the limit is rejected with the same ValidationException and
    # exact message StartExecution uses for an oversized input, and the task stays outstanding.
    too_big_output = _payload(_LIMIT + 1024)
    exec_arn2 = _start_execution(ctx, sm_arn)
    task_token2 = _poll_activity_task(ctx, act_arn)
    code, status, message = _error_code_and_message(
        lambda: sfn.send_task_success(taskToken=task_token2, output=too_big_output)
    )
    assert (code, status) == ("ValidationException", 400), (
        f"expected ValidationException/400 for a {len(too_big_output.encode())!r}-byte output, got "
        f"{code!r}/{status!r}: {message[:200]!r}"
    )
    expected_message = "1 validation error detected: Value at 'output' failed to satisfy constraint: Member must have size less than or equal to 262144 bytes in UTF-8 encoding"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # The task token must still be outstanding: a heartbeat on it still succeeds.
    sfn.send_task_heartbeat(taskToken=task_token2)
    desc = sfn.describe_execution(executionArn=exec_arn2)
    assert desc["status"] == "RUNNING", (
        f"execution should still be RUNNING after a rejected SendTaskSuccess, got {desc['status']!r}"
    )

    # Clean up by completing the outstanding task so the execution reaches a terminal state.
    sfn.send_task_failure(taskToken=task_token2, error="CleanupAfterRejectedOutput", cause="sim2real cleanup")
    final2 = _poll_execution_terminal(ctx, exec_arn2)
    assert final2["status"] == "FAILED", f"expected FAILED via cleanup SendTaskFailure, got {final2}"


def _payload(total_bytes: int) -> str:
    """A JSON object of exactly ``total_bytes`` bytes."""
    body = {"pad": ""}
    filler = total_bytes - len(json.dumps(body, separators=(",", ":")).encode())
    assert filler >= 0, f"{total_bytes!r} bytes is too small"
    body["pad"] = "x" * filler
    return json.dumps(body, separators=(",", ":"))


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return exc.response["Error"]["Code"], status, exc.response["Error"].get("Message") or ""
    raise AssertionError("SendTaskSuccess unexpectedly SUCCEEDED on an over-limit output")


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=arn), "ActivityDoesNotExist"))
    return arn


def _start_execution(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("sim2real-worker-"))
        if last.get("taskToken"):
            return last["taskToken"]
        time.sleep(2.0)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


def _poll_execution_terminal(ctx, exec_arn, *, timeout_s=90.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine covers it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"
            ))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
