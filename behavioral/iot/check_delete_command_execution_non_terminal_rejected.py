"""delete-command-execution-non-terminal-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-command-execution-non-terminal-rejected"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCommandExecution on a pending execution fails with ValidationException
    "Failed to delete command execution as it hasn't become terminal." and the execution
    is left intact."""
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-iot-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    command_id = ctx.unique_name("sim2real-cmd-")
    command_arn = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": json.dumps({"action": "reboot"}).encode("utf-8"), "contentType": "application/json"},
    )["commandArn"]
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    # StartCommandExecution is served by the unified IoT data-plane endpoint
    # (iot:Data-ATS), reached through the "iot-jobs-data" client (the "iot-data"
    # client's operation set does not include command-execution operations).
    data_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(data_endpoint))

    # this execution is never touched by a device, so it stays CREATED/IN_PROGRESS
    pending = jobs_data.start_command_execution(commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=600)
    pending_id = pending["executionId"]
    ctx.on_cleanup(lambda: _try_delete_execution(iot, pending_id, thing_arn))

    pending_status = iot.get_command_execution(executionId=pending_id, targetArn=thing_arn)["status"]
    assert pending_status in ("CREATED", "IN_PROGRESS"), (
        f"expected a non-terminal status right after start, got {pending_status!r}"
    )

    err = _error(lambda: iot.delete_command_execution(executionId=pending_id, targetArn=thing_arn))
    assert err == (
        "ValidationException",
        "Failed to delete command execution as it hasn't become terminal.",
    ), err

    # effect absent: the execution is still there, untouched, after the rejected delete
    still_there = iot.get_command_execution(executionId=pending_id, targetArn=thing_arn)
    assert still_there["executionId"] == pending_id, (
        f"expected the same execution {pending_id!r}, got {still_there['executionId']!r}"
    )
    assert still_there["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected the rejected delete to leave the execution non-terminal, got {still_there['status']!r}"
    )


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _try_delete_execution(iot, execution_id, target_arn):
    iot.delete_command_execution(executionId=execution_id, targetArn=target_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

