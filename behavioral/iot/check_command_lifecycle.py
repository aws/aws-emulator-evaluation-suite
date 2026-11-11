"""command-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "command-lifecycle"
GROUP = 'command'
SERVICES = ['iot']

def _try_not_found(fn, not_found_exc):
    """Call fn, returning its result, or None if it raised the specific not-found error.

    Any other exception propagates: swallowing every exception would let an
    unrelated failure (AccessDenied, throttling, ...) masquerade as "the
    resource is gone".
    """
    try:
        return fn()
    except not_found_exc:
        return None

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCommand -> Get -> Update -> deprecate -> Delete, with GetCommand reflecting
    each mutation and the deleted command becoming unresolvable."""
    iot = ctx.client("iot")
    command_id = ctx.unique_name("sim2real-behav-cmd-")
    iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        displayName="probe command",
        description="probe",
        # The AWS-IoT namespace requires a payload.
        payload={
            "content": json.dumps({"operation": "reboot"}).encode("utf-8"),
            "contentType": "application/json",
        },
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Deprecation is a prerequisite for a clean delete (LIFO: deprecate, then delete).
    def _cleanup(_n=command_id):
        try:
            iot.update_command(commandId=_n, deprecated=True)
            iot.delete_command(commandId=_n)
        except iot.exceptions.ResourceNotFoundException:
            pass  # already reaped
        except iot.exceptions.ConflictException as exc:
            if "pending deletion" not in str(exc):
                raise  # only the check's own soft delete is an expected conflict

    ctx.on_cleanup(_cleanup)

    got = iot.get_command(commandId=command_id)
    assert got["commandId"] == command_id, got["commandId"]
    assert got["displayName"] == "probe command", got["displayName"]
    assert got.get("deprecated", False) is False, got.get("deprecated")

    iot.update_command(commandId=command_id, displayName="renamed command")
    got2 = iot.get_command(commandId=command_id)
    assert got2["displayName"] == "renamed command", got2["displayName"]

    ids = [c["commandId"] for c in iot.list_commands().get("commands", [])]
    assert command_id in ids, f"{command_id} missing from ListCommands"

    # Deprecation is a prerequisite state for a clean delete.
    iot.update_command(commandId=command_id, deprecated=True)
    got3 = iot.get_command(commandId=command_id)
    assert got3["deprecated"] is True, got3

    iot.delete_command(commandId=command_id)

    # DeleteCommand is a SOFT delete: the command stays readable with pendingDeletion=True
    # and is reaped asynchronously, so it must not vanish synchronously.
    not_found = iot.exceptions.ResourceNotFoundException
    state = _eventually(
        lambda: _try_not_found(lambda: iot.get_command(commandId=command_id), not_found),
        lambda r: r is not None and r.get("pendingDeletion") is True,
        timeout_s=60,
    )
    assert state is not None and state.get("pendingDeletion") is True, (
        f"expected the deleted command to stay readable with pendingDeletion=True, got {state!r}"
    )
    if state is not None:
        # A mutation on the soft-deleted id must also be rejected — it is not just
        # unresolvable-by-convention, it is genuinely unusable. Real AWS refuses this
        # with ConflictException (the id still exists, pending deletion), not
        # ResourceNotFoundException.
        try:
            iot.update_command(commandId=command_id, displayName="post-delete-mutation")
        except iot.exceptions.ConflictException as exc:
            message = exc.response["Error"].get("Message")
            expected = f"Failed to update command {command_id} as it's pending deletion."
            assert message == expected, f"expected message {expected!r}, got {message!r}"
        else:
            raise AssertionError(
                "UpdateCommand succeeded against a soft-deleted (pendingDeletion=True) command"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
