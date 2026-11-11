"""start-application-transitions-to-started."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-application-transitions-to-started"
GROUP = "state-transitions"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartApplication drives a CREATED application through STARTING to STARTED."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "CREATED",
        timeout_s=60.0,
        interval_s=3.0,
    )

    emrs.start_application(applicationId=app_id)

    final_state = _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s != "STARTING",
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_state == "STARTED", f"expected application {app_id} to reach STARTED, got {final_state!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cleanup_application(emrs, app_id):
    try:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if state in ("STARTED", "STARTING"):
        try:
            emrs.stop_application(applicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                state = emrs.get_application(applicationId=app_id)["application"]["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "STOPPED":
                break
            time.sleep(5)
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
