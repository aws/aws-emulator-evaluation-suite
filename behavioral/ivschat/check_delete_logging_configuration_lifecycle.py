"""delete-logging-configuration-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-logging-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["ivschat"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last={last!r}")


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


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real": "ivschat-delete-logging-configuration-lifecycle"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLoggingConfiguration removes an unattached ACTIVE config: Get, Update and a second Delete then
    all fail with ResourceNotFoundException "Resource: <arn> not found", so the deleted id stays gone."""
    logs = ctx.client("logs")
    ivschat = ctx.client("ivschat")

    log_group = ctx.unique_name("/sim2real/ivschat-del-")
    logs.create_log_group(logGroupName=log_group, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    created = ivschat.create_logging_configuration(
        name=ctx.unique_name("sim2real-ivschat-logcfg"),
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group}},
        tags=dict(_MANAGED_TAGS),
    )
    arn = created["arn"]
    _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=arn),
        lambda r: r["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    ivschat.delete_logging_configuration(identifier=arn)

    final_code, final_message = _wait_for_error(
        lambda: ivschat.get_logging_configuration(identifier=arn), timeout_s=60.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected GetLoggingConfiguration on a deleted config to fail ResourceNotFoundException, "
        f"got {final_code!r}"
    )
    assert final_message == f"Resource: {arn} not found", f"unexpected message: {final_message!r}"

    update_code, update_message = _client_error(
        lambda: ivschat.update_logging_configuration(
            identifier=arn,
            name=ctx.unique_name("sim2real-ivschat-logcfg-dead"),
            destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group}},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateLoggingConfiguration against the deleted identifier to also fail "
        f"ResourceNotFoundException (it must stay dead, not resurrect or silently succeed), "
        f"got {update_code!r}"
    )
    assert update_message == f"Resource: {arn} not found", f"unexpected message: {update_message!r}"

    redelete_code, redelete_message = _client_error(
        lambda: ivschat.delete_logging_configuration(identifier=arn)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteLoggingConfiguration against the same dead identifier to fail "
        f"ResourceNotFoundException, not succeed silently, got {redelete_code!r}"
    )
    assert redelete_message == f"Resource: {arn} not found", f"unexpected message: {redelete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
