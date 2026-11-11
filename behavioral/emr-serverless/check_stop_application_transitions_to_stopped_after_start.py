"""stop-application-transitions-to-stopped-after-start."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-application-transitions-to-stopped-after-start"
GROUP = "state-transitions"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopApplication drives a STARTED application through STOPPING to STOPPED."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    emrs.start_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STARTED",
        timeout_s=300.0,
        interval_s=5.0,
    )

    emrs.stop_application(applicationId=app_id)
    final_state = _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STOPPED",
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_state == "STOPPED", f"expected STOPPED after StopApplication, got {final_state!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
