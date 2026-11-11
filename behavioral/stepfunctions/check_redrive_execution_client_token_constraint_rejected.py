"""redrive-execution-client-token-constraint-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-client-token-constraint-rejected"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]

_SFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

# Each value fails the clientToken constraint (length>=1, pattern ^[!-~]+$, i.e. printable
# ASCII with no whitespace) a different way: empty, blank, interior whitespace, non-ASCII.
_BAD_TOKENS = ("", " ", "a b", "café")


def _create_sfn_role(ctx):
    """An execution role this check creates, trusted by states.amazonaws.com."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SFN_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn, name=name, definition=json.dumps(definition), roleArn=_create_sfn_role(ctx),
        type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _fail_definition():
    return {"StartAt": "F", "States": {"F": {"Type": "Fail", "Error": "BoomAlways", "Cause": "deliberate"}}}


def _start_execution(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"))["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _expected_message(value: str) -> str:
    """The ValidationException message clientToken's length (>=1) and pattern (^[!-~]+$) earn."""
    violations = [
        f"Value '{value}' at 'clientToken' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [!-~]+"
    ]
    if len(value) < 1:
        violations.append(
            f"Value '{value}' at 'clientToken' failed to satisfy constraint: "
            "Member must have length greater than or equal to 1"
        )
    noun = "error" if len(violations) == 1 else "errors"
    return f"{len(violations)} validation {noun} detected: " + "; ".join(violations)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution's clientToken rejects empty, blank, interior-whitespace and non-ASCII
    values with ValidationException naming the exact value and constraint, while a valid
    token on the same execution is accepted."""
    sfn = ctx.client("stepfunctions", config=Config(parameter_validation=False))

    fail_arn = _create_state_machine(ctx, _fail_definition())
    exec_arn = _start_execution(ctx, fail_arn)
    failed = _wait_terminal(ctx, exec_arn, timeout_s=30)
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed!r}"

    for bad_token in _BAD_TOKENS:
        code, message = _error(
            lambda bad_token=bad_token: sfn.redrive_execution(
                executionArn=exec_arn, clientToken=bad_token)
        )
        assert code == "ValidationException", (
            f"expected ValidationException for clientToken={bad_token!r}, got {code}"
        )
        expected = _expected_message(bad_token)
        assert message == expected, (
            f"for clientToken={bad_token!r} expected message {expected!r}, got {message!r}"
        )

    # ---- effect absent: the execution is untouched by every refused redrive ----
    after = sfn.describe_execution(executionArn=exec_arn)
    assert after.get("redriveCount", 0) == 0, (
        f"expected redriveCount to stay 0 after only refused redrives, got {after!r}"
    )

    # ---- positive control: a valid clientToken on the same execution is accepted ----
    good = sfn.redrive_execution(executionArn=exec_arn, clientToken="sim2real-good-token")
    assert "redriveDate" in good, f"expected redriveDate in a successful redrive, got {good!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
