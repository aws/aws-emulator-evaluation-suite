"""wait-seconds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-seconds"
GROUP = 'wait_state'
SERVICES = ['stepfunctions']

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    A Pass/Wait-only state machine makes no AWS call on the customer's behalf, so the role
    needs no permissions; a role the check did not create is account configuration.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying the AccessDeniedException a fresh role gives while IAM
    propagates; IAM exposes no condition to poll for that, so the bounded retry is the wait."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


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


def _run_to_completion(ctx, arn, input_data=None, *, timeout_s=30):
    """Start an execution of `arn` and return (terminal describe, seconds from start)."""
    start = time.monotonic()
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    result = _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)
    return result, time.monotonic() - start


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Wait state with Seconds=1 delays then proceeds to SUCCEEDED."""
    definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "Seconds": 1, "Next": "Done"},
            "Done": {"Type": "Pass", "Result": "waited", "End": True},
        },
    }
    arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    result, elapsed = _run_to_completion(ctx, arn, {})
    assert result["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {result['status']!r}: {result!r}"
    )
    assert _get_output(result) == "waited", (
        f"expected output 'waited', got {_get_output(result)!r}"
    )
    assert elapsed >= 0.8, f"Wait too short: {elapsed:.2f}s, expected >= 0.8s for Seconds=1"
    assert elapsed < 5.0, (
        f"Wait too long: {elapsed:.2f}s, expected well under 5s for a declared Seconds=1 wait"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
