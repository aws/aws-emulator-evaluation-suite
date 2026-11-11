"""auto-stop-configuration-stops-idle-application."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "auto-stop-configuration-stops-idle-application"
GROUP = "state-transitions"
SERVICES = ["emr-serverless"]

#: Real-AWS wall bounds: starting the application, then the 1-minute idle timeout plus the stop.
_STARTED_DEADLINE_S = 300.0
_STOPPED_DEADLINE_S = 480.0


# timing:real-time — ttl: 60 s
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """An application with autoStopConfiguration idleTimeoutMinutes=1 goes from STARTED to STOPPED on its own
    once idle past that timeout, without a StopApplication call."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        autoStopConfiguration={"enabled": True, "idleTimeoutMinutes": 1},
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _stop_then_delete(emrs, app_id))

    emrs.start_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STARTED",
        timeout_s=_budget_s(ctx, _STARTED_DEADLINE_S),
        interval_s=2.0,
        ctx=ctx,
    )

    final_state = _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STOPPED",
        timeout_s=_budget_s(ctx, _STOPPED_DEADLINE_S),
        interval_s=2.0,
        ctx=ctx,
    )
    assert final_state == "STOPPED", f"expected auto-stop to reach STOPPED, last state={final_state!r}"


def _stop_then_delete(emrs, app_id):
    state = emrs.get_application(applicationId=app_id)["application"]["state"]
    if state in ("STARTED", "STARTING"):
        emrs.stop_application(applicationId=app_id)
        _poll_until(
            lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
            lambda s: s == "STOPPED",
            timeout_s=300.0,
            interval_s=5.0,
        )
    emrs.delete_application(applicationId=app_id)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"run budget ended after {timeout_s:.0f}s of waiting (last={last!r}); not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
