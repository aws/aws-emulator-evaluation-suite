"""delete-logging-configuration-conflict-while-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-logging-configuration-conflict-while-attached-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivschat"]


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_for_error(fn, *, timeout_s=60.0, interval_s=2.0):
    """Re-call fn() until it raises a ClientError and return its (code, message); raise if it
    still succeeds when the budget runs out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded after {timeout_s}s; last={last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last={last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLoggingConfiguration on a config still attached to a room is rejected with
    ConflictException and the config is left fully intact (still ACTIVE, still gettable) --
    while detaching it first and retrying the same delete succeeds (control)."""
    logs = ctx.client("logs")
    ivschat = ctx.client("ivschat")

    log_group = ctx.unique_name("/sim2real/ivschat-attach-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cfg = ivschat.create_logging_configuration(
        name=ctx.unique_name("sim2real-ivschat-logcfg"),
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group}},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    cfg_arn = cfg["arn"]
    _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=cfg_arn),
        lambda r: r["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    room = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"),
        loggingConfigurationIdentifiers=[cfg_arn],
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    room_arn = room["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    def _cleanup_cfg():
        from botocore.exceptions import ClientError

        try:
            ivschat.delete_logging_configuration(identifier=cfg_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cfg)

    code, message = _client_error(lambda: ivschat.delete_logging_configuration(identifier=cfg_arn))
    assert code == "ConflictException", (
        f"expected ConflictException deleting a logging config still attached to a room, got {code!r}"
    )
    assert message == (
        f"Unable to perform ivschat:DeleteLoggingConfiguration while {cfg_arn} is still attached "
        "to a chat room"
    ), f"unexpected message: {message!r}"

    still_there = ivschat.get_logging_configuration(identifier=cfg_arn)
    assert still_there["state"] == "ACTIVE", (
        f"expected the rejected delete to leave the config ACTIVE, got {still_there['state']!r}"
    )

    ivschat.update_room(identifier=room_arn, loggingConfigurationIdentifiers=[])
    ivschat.delete_logging_configuration(identifier=cfg_arn)

    final_code, final_message = _wait_for_error(
        lambda: ivschat.get_logging_configuration(identifier=cfg_arn), timeout_s=60.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected the retried delete (after detaching) to leave the config gone with "
        f"ResourceNotFoundException, got {final_code!r}"
    )
    assert final_message == f"Resource: {cfg_arn} not found", f"unexpected message: {final_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
