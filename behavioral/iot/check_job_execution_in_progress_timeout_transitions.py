"""job-execution-in-progress-timeout-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "job-execution-in-progress-timeout-transitions"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iot"]


# timing:real-time — workflow: 60 s
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A job execution left IN_PROGRESS past inProgressTimeoutInMinutes auto-transitions
    to TIMED_OUT with no client action, purely from the server-side timer."""
    iot = ctx.client("iot")
    jobs_endpoint = ctx.endpoint_url(iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"])
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=jobs_endpoint)

    thing_name = ctx.unique_name("sim2real-iot-jobtmo-thing-")
    # Things are not a taggable resource type for TagResource (real AWS: "Invalid resource
    # type in ARN: thing"); the unique-prefixed name identifies it instead.
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    job_id = ctx.unique_name("sim2real-iot-jobtmo-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        targetSelection="SNAPSHOT",
        document=json.dumps({"operation": "noop"}),
        # Minimum allowed value; AWS docs: "timeout interval can be anywhere between 1
        # minute and 7 days ... the actual job execution timeout can occur up to 60
        # seconds later than the estimated duration."
        timeoutConfig={"inProgressTimeoutInMinutes": 1},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    # Wait (read-only) until the execution is queued for the thing, then move it to
    # IN_PROGRESS the same way a real device would, by pulling its next pending execution
    # from the Jobs data plane once. This starts the timeout timer.
    _poll_until(
        lambda: jobs_data.get_pending_job_executions(thingName=thing_name).get("queuedJobs", []),
        lambda queued: any(j.get("jobId") == job_id for j in queued),
        timeout_s=30.0,
        interval_s=2.0,
    )
    started = jobs_data.start_next_pending_job_execution(thingName=thing_name)
    assert started["execution"]["status"] == "IN_PROGRESS", (
        f"expected IN_PROGRESS after start_next_pending_job_execution, "
        f"got {started['execution']['status']!r}"
    )
    in_progress_since = time.monotonic()

    # Two-sided: the configured timeout is 1 minute, so a target that transitions the
    # execution before that boundary is wrong in the other direction from a target that
    # never transitions it at all. Hold a window comfortably below the boundary and demand
    # the execution stays IN_PROGRESS on every sample -- this is what catches a stub that
    # times out immediately instead of honoring inProgressTimeoutInMinutes.
    early_deadline = time.monotonic() + 20.0
    while time.monotonic() < early_deadline:
        early = iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"]
        assert early["status"] == "IN_PROGRESS", (
            f"execution transitioned to {early['status']!r} at "
            f"{time.monotonic() - in_progress_since:.1f}s, well under the configured 60s "
            f"inProgressTimeoutInMinutes -- the timeout fired too early"
        )
        time.sleep(5.0)

    # Never call UpdateJobExecution again: we want the server-side timer alone to expire
    # the execution. Poll for the automatic transition, allowing the documented slack.
    final = _poll_until(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"],
        lambda e: e["status"] != "IN_PROGRESS",
        timeout_s=240.0,
        interval_s=5.0,
    )
    elapsed = time.monotonic() - in_progress_since
    assert final["status"] == "TIMED_OUT", (
        f"expected TIMED_OUT after the configured 60s inProgressTimeoutInMinutes "
        f"(elapsed={elapsed:.1f}s), got {final['status']!r}"
    )
    # Upper bound: the 60s configured timeout plus AWS's documented slack (the timeout can fire
    # up to 60s late) plus a sweep-interval margin, well inside the poll deadline above, so a
    # target that reaches TIMED_OUT by some much longer mechanism does not read as correct.
    assert elapsed <= 180.0, (
        f"TIMED_OUT observed at {elapsed:.1f}s after IN_PROGRESS, past the 180s ceiling "
        f"(60s configured timeout + 60s documented slack + 60s margin)"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
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
