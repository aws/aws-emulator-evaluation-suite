"""command-execution-state-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "command-execution-state-transitions"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A command execution with no device response moves to TIMED_OUT after its
    executionTimeoutSeconds; DeleteCommandExecution then fails with ValidationException
    "... hasn't become terminal.", and the execution and command stay readable."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint))

    command_id = ctx.unique_name("sim2real-cmd-")
    command = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action": "noop"}', "contentType": "application/json"},
    )
    ctx.on_cleanup(lambda: _delete_command_quiet(iot, command_id))
    command_arn = command["commandArn"]

    thing_name = ctx.unique_name("sim2real-cmd-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    started = jobs_data.start_command_execution(
        commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=6
    )
    execution_id = started["executionId"]

    initial = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    assert initial["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected a freshly started execution to be CREATED/IN_PROGRESS, "
        f"got status={initial['status']!r}"
    )

    # No real device is connected to pick this up, so the execution's own timer expires
    # and it lands in the terminal TIMED_OUT state (documented behavior of
    # executionTimeoutSeconds).
    final = _poll_until(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn),
        lambda e: e["status"] == "TIMED_OUT",
        timeout_s=40.0,
        interval_s=2.0,
    )
    assert final["status"] == "TIMED_OUT", (
        f"expected the unacknowledged execution to reach TIMED_OUT within 40s, "
        f"last observed status={final['status']!r}"
    )

    # TIMED_OUT is not one of the statuses DeleteCommandExecution treats as deletable.
    code = _error_code(lambda: iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn))
    assert code == ("ValidationException", "Failed to delete command execution as it hasn't become terminal."), f"expected ValidationException, got {code!r}"

    # The execution is unaffected by the rejected delete.
    still_there = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    assert still_there["executionId"] == execution_id, (
        f"expected the rejected delete to leave {execution_id!r} retrievable, "
        f"got executionId={still_there['executionId']!r}"
    )
    assert still_there["status"] == "TIMED_OUT", (
        f"expected the rejected delete to leave the execution's status unchanged at "
        f"TIMED_OUT, got status={still_there['status']!r}"
    )

    # The command definition's lifecycle is independent of its executions.
    still_there_cmd = iot.get_command(commandId=command_id)
    assert still_there_cmd["commandId"] == command_id, (
        f"expected the command definition {command_id!r} to be unaffected by its "
        f"execution's TIMED_OUT transition, got commandId={still_there_cmd['commandId']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_command_quiet(iot, command_id):
    iot.delete_command(commandId=command_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
