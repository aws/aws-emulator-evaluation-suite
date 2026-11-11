"""stop-execution-oversized-error-rejected-execution-keeps-running."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-execution-oversized-error-rejected-execution-keeps-running"
GROUP = "execution-lifecycle"
SERVICES = ["stepfunctions"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_machine(ctx, sfn, iam) -> str:
    """A STANDARD state machine parked in a long Wait state, with its own execution role."""
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name,
                               AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    definition = json.dumps({"StartAt": "Park",
                             "States": {"Park": {"Type": "Wait", "Seconds": 3600, "End": True}}})
    name = ctx.unique_name("sim2real-behav-sm-stop-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                           tags=[{"key": "sim2real", "value": CHECK}])["stateMachineArn"]
            break
        except ClientError as exc:
            # IAM propagation: the new role is not yet assumable, and nothing observes that.
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return arn


def _start(ctx, sfn, sm_arn: str) -> str:
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    return exec_arn


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _wait_entered(sfn, exec_arn: str) -> None:
    """Poll until the execution's history shows it parked in the Wait state."""
    deadline = time.monotonic() + 60
    types: list = []
    while time.monotonic() < deadline:
        types = [e["type"] for e in sfn.get_execution_history(executionArn=exec_arn)["events"]]
        if "WaitStateEntered" in types:
            return
        time.sleep(1)
    raise AssertionError(f"the execution never entered its Wait state; history types {types!r}")


def _history(sfn, exec_arn: str) -> list:
    events = []
    kwargs = {"executionArn": exec_arn}
    while True:
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        if not page.get("nextToken"):
            return events
        kwargs["nextToken"] = page["nextToken"]


def _terminal_history(sfn, exec_arn: str) -> list:
    """The full history once it records ExecutionAborted (it may trail DescribeExecution)."""
    deadline = time.monotonic() + 60
    events: list = []
    while time.monotonic() < deadline:
        events = _history(sfn, exec_arn)
        if any(e["type"] == "ExecutionAborted" for e in events):
            return events
        time.sleep(1)
    raise AssertionError(f"history never recorded ExecutionAborted: {[e['type'] for e in events]!r}")


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopExecution with a 257-character error or a 32769-character cause is a ValidationException
    naming the violated length and leaves the execution RUNNING with no ExecutionAborted event; the
    boundary values (256 and 32768 characters) stop it and are recorded verbatim.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sm_arn = _wait_machine(ctx, sfn, iam)
    exec_arn = _start(ctx, sfn, sm_arn)
    _wait_entered(sfn, exec_arn)

    code, msg = _error(lambda: sfn.stop_execution(executionArn=exec_arn, error="e" * 257))
    assert (code, msg) == (
        "ValidationException",
        "1 validation error detected: Value at 'error' failed to satisfy constraint: "
        "Member must have length less than or equal to 256",
    ), f"a 257-character error was refused with {code!r} / {msg!r}"
    code, msg = _error(lambda: sfn.stop_execution(executionArn=exec_arn, cause="c" * 32769))
    assert (code, msg) == (
        "ValidationException",
        "1 validation error detected: Value at 'cause' failed to satisfy constraint: "
        "Member must have length less than or equal to 32768",
    ), f"a 32769-character cause was refused with {code!r} / {msg!r}"

    still = sfn.describe_execution(executionArn=exec_arn)
    assert still["status"] == "RUNNING", f"a refused stop left the execution {still['status']!r}"
    types = [e["type"] for e in _history(sfn, exec_arn)]
    assert "ExecutionAborted" not in types, f"a refused stop appended ExecutionAborted: {types!r}"

    error, cause = "e" * 256, "c" * 32768
    sfn.stop_execution(executionArn=exec_arn, error=error, cause=cause)
    done = sfn.describe_execution(executionArn=exec_arn)
    assert done["status"] == "ABORTED", f"the boundary-valued stop left the execution {done['status']!r}"
    assert (len(done.get("error", "")), len(done.get("cause", ""))) == (256, 32768), (
        f"DescribeExecution recorded an error of {len(done.get('error', ''))} and a cause of "
        f"{len(done.get('cause', ''))} characters"
    )
    assert (done["error"], done["cause"]) == (error, cause), "DescribeExecution altered the error or cause"
    details = _terminal_history(sfn, exec_arn)[-1].get("executionAbortedEventDetails")
    assert details == {"error": error, "cause": cause}, (
        f"ExecutionAborted details carry keys {sorted(details or {})!r} and differ from the stop's values"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
