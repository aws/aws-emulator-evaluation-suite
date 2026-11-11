"""data-plane-command-execution-payload-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-plane-command-execution-payload-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A binary CreateCommand payload survives byte-for-byte through repeated GetCommand calls;
    DeleteCommand soft-deletes, so GetCommand reports it deprecated and pending deletion and
    UpdateCommand on it is rejected with ConflictException."""
    iot = ctx.client("iot")

    command_id = ctx.unique_name("sim2real-iot-cmd-")
    payload_bytes = bytes(range(256)) * 4  # deterministic, non-text-safe binary content

    created = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        displayName="sim2real command",
        payload={"content": payload_bytes, "contentType": "application/octet-stream"},
        tags=[{"Key": "sim2real", "Value": "command-payload-round-trip"}],
    )
    command_arn = created["commandArn"]

    got_command = iot.get_command(commandId=command_id)
    assert got_command["commandId"] == command_id
    assert got_command["commandArn"] == command_arn
    assert got_command["payload"]["content"] == payload_bytes
    assert got_command["payload"]["contentType"] == "application/octet-stream"

    # A second, independent GetCommand call must keep returning the exact same bytes -- not
    # a truncated, re-encoded, or stale value.
    got_command_again = iot.get_command(commandId=command_id)
    assert got_command_again["payload"]["content"] == payload_bytes
    assert got_command_again["payload"]["contentType"] == "application/octet-stream"

    iot.delete_command(commandId=command_id)
    ctx.on_cleanup(lambda: _delete_command_when_terminal(iot, command_id))

    # DeleteCommand soft-deletes: an independent GetCommand still succeeds, but the command is
    # now flagged deprecated and pending permanent deletion. The payload survives untouched.
    after_delete = iot.get_command(commandId=command_id)
    assert after_delete["deprecated"] is True, after_delete
    assert after_delete["pendingDeletion"] is True, after_delete
    assert after_delete["payload"]["content"] == payload_bytes

    try:
        iot.update_command(commandId=command_id, description="should be rejected")
    except iot.exceptions.ConflictException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Failed to update command {command_id} as it's pending deletion."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"UpdateCommand({command_id!r}) succeeded against a command pending deletion"
        )


# ===== helpers =====
def _delete_command_when_terminal(iot, command_id: str, timeout_s: float = 10.0) -> None:
    """Delete the command, retrying while it still conflicts; raise any other failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.delete_command(commandId=command_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

