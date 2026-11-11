"""sfn-retry-exhaustion-routes-to-catch-and-the-success-state-is-never-entered."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-retry-exhaustion-routes-to-catch-and-the-success-state-is-never-entered"
GROUP = 'error_handling'
SERVICES = ['stepfunctions']

#: The error the branch's Fail state raises; the Retry and the Catch both key on it, so a wrong
#: name is loud rather than silent (the state fails once, nothing retries, and no Catch fires).
_ERROR_NAME = "Sim2Real.Boom"
_MAX_ATTEMPTS = 2


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A state that always fails is retried exactly MaxAttempts times, then routed to Catch —
    and the success state that follows it is never entered.
    """
    sfn = ctx.client("stepfunctions")

    _role_name, role_arn = _create_sfn_role(ctx, [])

    definition = {
        "Comment": "one retryable+catchable Parallel state, a success path and a handler path",
        "StartAt": "Work",
        "States": {
            "Work": {
                "Type": "Parallel",
                "Branches": [{
                    "StartAt": "Decide",
                    "States": {
                        "Decide": {
                            "Type": "Choice",
                            "Choices": [{"Variable": "$.boom", "BooleanEquals": True, "Next": "Boom"}],
                            "Default": "Fine",
                        },
                        "Boom": {"Type": "Fail", "Error": _ERROR_NAME, "Cause": "sim2real always-failing branch"},
                        "Fine": {"Type": "Pass", "End": True},
                    },
                }],
                "Retry": [{
                    "ErrorEquals": [_ERROR_NAME],
                    "MaxAttempts": _MAX_ATTEMPTS,
                    "IntervalSeconds": 1,
                    "BackoffRate": 1.0,
                }],
                "Catch": [{
                    "ErrorEquals": [_ERROR_NAME],
                    "Next": "HANDLER",
                    "ResultPath": "$.failure",
                }],
                "ResultPath": "$.worked",
                "Next": "NEXT",
            },
            "NEXT": {
                "Type": "Pass",
                "Parameters": {"handled": False, "reached": "NEXT"},
                "End": True,
            },
            "HANDLER": {
                "Type": "Pass",
                "Parameters": {"handled": True, "reached": "HANDLER", "error.$": "$.failure.Error"},
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # The input steers the Parallel's one branch into its Fail state, raised inside Step Functions.
    failing = _run_to_terminal(ctx, sm_arn, {"boom": True})
    assert failing["status"] == "SUCCEEDED", (
        f'the catch path should have ended the execution successfully; it was '
        f'{failing["status"]!r}: {failing.get("error")!r} {failing.get("cause")!r}'
    )
    failing_output = json.loads(failing["output"])
    assert failing_output == {"handled": True, "reached": "HANDLER", "error": _ERROR_NAME}, (
        f"the execution did not end in the catch handler with {_ERROR_NAME!r}: output was "
        f"{failing_output!r}"
    )

    history = _full_history(ctx, failing["executionArn"])
    types = [e["type"] for e in history]
    started = types.count("ParallelStateStarted")
    assert started == _MAX_ATTEMPTS + 1, (
        f"the Parallel state was started {started!r} times for MaxAttempts={_MAX_ATTEMPTS!r}; "
        f"expected {_MAX_ATTEMPTS + 1!r} (the first attempt plus the retries). "
        f"history was {types!r}"
    )

    entered = _entered_state_names(history)
    booms = entered.count("Boom")
    assert booms == _MAX_ATTEMPTS + 1, (
        f"the failing branch's Fail state was entered {booms!r} times; expected "
        f"{_MAX_ATTEMPTS + 1!r}, one per attempt. states entered were {entered!r}"
    )
    assert entered.count("Work") == 1, (
        f"the retried Parallel state must be entered once, got {entered.count('Work')!r}: {entered!r}"
    )
    assert "HANDLER" in entered, (
        f"the catch handler was never entered; states entered were {entered!r}"
    )
    assert "NEXT" not in entered, (
        f"the post-task success state was entered despite exhausted retries: {entered!r}"
    )

    # Positive control: an input that makes the branch SUCCEED must enter NEXT, never HANDLER.
    succeeding = _run_to_terminal(ctx, sm_arn, {"boom": False})
    assert succeeding["status"] == "SUCCEEDED", (
        f'the control execution was {succeeding["status"]!r}: '
        f'{succeeding.get("error")!r} {succeeding.get("cause")!r}'
    )
    control_output = json.loads(succeeding["output"])
    assert control_output == {"handled": False, "reached": "NEXT"}, (
        f"the control execution output was {control_output!r}, expected the NEXT branch"
    )
    control_history = _full_history(ctx, succeeding["executionArn"])
    control_entered = _entered_state_names(control_history)
    assert "NEXT" in control_entered and "HANDLER" not in control_entered, (
        f"the control execution entered {control_entered!r}; it must enter NEXT and never HANDLER"
    )
    control_started = [e["type"] for e in control_history].count("ParallelStateStarted")
    assert control_started == 1, (
        f"the control execution started the Parallel state {control_started!r} times, expected 1"
    )


def _create_sfn_role(ctx, statements):
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
    policy_name = f"{role_name}-policy"

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
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=120.0, max_attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _full_history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


def _entered_state_names(history):
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in history
        if e["type"].endswith("StateEntered")
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
