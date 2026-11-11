"""send-task-success-invalid-output-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-invalid-output-rejected"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machines here call no AWS API on the customer's behalf, so the role carries no
    permissions. It is created rather than looked up because a role the check did not create
    is account configuration, not a service contract.
    """
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
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying the one error IAM propagation can produce.

    A freshly created role is not instantly assumable and IAM exposes no condition to poll
    for that, so the bounded AccessDeniedException retry is the wait.
    """
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    # GetActivityTask long-polls up to ~60s server-side; use a fresh client and retry until a token appears.
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskSuccess with malformed JSON output fails with InvalidOutput and the exact message and
    leaves the task outstanding (a later SendTaskFailure ends the execution FAILED), while valid output
    on the same wiring completes an execution with exactly that output."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    definition = {
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act["arn"], "TimeoutSeconds": 300, "End": True}},
    }
    arn = _create_state_machine(ctx, definition)

    # Positive control: a syntactically valid JSON output on the same activity/state
    # machine completes the execution normally.
    control_exec_arn = _start_execution(ctx, arn)
    control_task = _poll_activity_task(ctx, act["arn"])
    control_output = {"result": 1}
    sfn.send_task_success(taskToken=control_task["taskToken"], output=json.dumps(control_output))
    control_final = _wait_execution_complete(ctx, control_exec_arn, timeout_s=60)
    assert control_final["status"] == "SUCCEEDED", f"positive control did not succeed: {control_final}"
    assert json.loads(control_final["output"]) == control_output, (
        f"positive control output mismatch: {control_final.get('output')}"
    )

    exec_arn = _start_execution(ctx, arn)
    task = _poll_activity_task(ctx, act["arn"])

    malformed_output = '{"result": 1'  # missing closing brace
    error = _client_error(lambda: sfn.send_task_success(taskToken=task["taskToken"], output=malformed_output))
    assert error.get("Code") == "InvalidOutput", f"expected InvalidOutput, got {error!r}"
    expected_message = f"Invalid Output: '{malformed_output}' is not valid JSON."
    assert error.get("Message") == expected_message, (
        f"expected InvalidOutput message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The task token must still be outstanding after the rejected call — clean up by
    # actually completing it so the execution reaches a terminal state.
    sfn.send_task_failure(taskToken=task["taskToken"], error="CleanupAfterRejectedOutput", cause="test cleanup")
    final = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert final["status"] == "FAILED", f"expected FAILED via cleanup SendTaskFailure, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
