"""command-execution-delete-non-terminal-rejected."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "command-execution-delete-non-terminal-rejected"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCommandExecution on a CREATED or IN_PROGRESS execution fails with
    ValidationException "Failed to delete command execution as it hasn't become
    terminal." and the execution is still retrievable."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint))

    command_id = ctx.unique_name("sim2real-cmd-rej-")
    command = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action": "noop"}', "contentType": "application/json"},
    )
    ctx.on_cleanup(lambda: _delete_command_quiet(iot, command_id))
    command_arn = command["commandArn"]

    thing_name = ctx.unique_name("sim2real-cmd-rej-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    started = jobs_data.start_command_execution(
        commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=30
    )
    execution_id = started["executionId"]

    initial = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    assert initial["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected a freshly started execution to be CREATED or IN_PROGRESS, got {initial['status']!r}"
    )

    # Break exactly one thing: try to delete while still non-terminal.
    code = _error_code(lambda: iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn))
    assert code == ("ValidationException", "Failed to delete command execution as it hasn't become terminal."), f"expected ValidationException, got {code!r}"

    # Effect absent: the execution is still there, unaffected by the rejected delete.
    still_there = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    assert still_there["executionId"] == execution_id, (
        f"expected the rejected delete to leave executionId={execution_id!r} intact, "
        f"got {still_there['executionId']!r}"
    )
    assert still_there["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected the rejected delete to leave status CREATED/IN_PROGRESS, got {still_there['status']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_command_quiet(iot, command_id):
    iot.delete_command(commandId=command_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
