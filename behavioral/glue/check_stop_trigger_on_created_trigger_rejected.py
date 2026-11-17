"""stop-trigger-on-created-trigger-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-trigger-on-created-trigger-rejected"
GROUP = "trigger"
SERVICES = ["glue"]

_INVALID_STATE_FOR_STOP = (
    "InvalidInputException",
    "The operation is not allowed when trigger is in state: CREATED",
)


def _error(fn):
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopTrigger on a trigger still in CREATED state is rejected, and the same trigger's
    StopTrigger succeeds once StartTrigger has moved it to ACTIVATED.
    """
    glue = ctx.client("glue")
    trigger_name = ctx.unique_name("sim2real-behav-trigger-")

    glue.create_trigger(
        Name=trigger_name,
        Type="SCHEDULED",
        Schedule="cron(0 12 * * ? *)",
        Actions=[{"JobName": ctx.unique_name("sim2real-behav-nonexistent-job-")}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=trigger_name))

    state = glue.get_trigger(Name=trigger_name)["Trigger"]["State"]
    assert state == "CREATED", f"a fresh trigger should be CREATED, got {state!r}"

    code, message = _error(lambda: glue.stop_trigger(Name=trigger_name))
    assert (code, message) == _INVALID_STATE_FOR_STOP, (
        f"StopTrigger on a CREATED trigger returned ({code!r}, {message!r}), "
        f"expected {_INVALID_STATE_FOR_STOP!r}"
    )

    glue.start_trigger(Name=trigger_name)
    activated = _poll_until(
        lambda: glue.get_trigger(Name=trigger_name)["Trigger"]["State"],
        lambda s: s == "ACTIVATED",
        timeout_s=60, interval_s=3,
    )
    assert activated == "ACTIVATED", activated

    glue.stop_trigger(Name=trigger_name)
    deactivated = _poll_until(
        lambda: glue.get_trigger(Name=trigger_name)["Trigger"]["State"],
        lambda s: s == "DEACTIVATED",
        timeout_s=60, interval_s=3,
    )
    assert deactivated == "DEACTIVATED", (
        f"StopTrigger on the now-ACTIVATED trigger should settle it to DEACTIVATED, got {deactivated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
