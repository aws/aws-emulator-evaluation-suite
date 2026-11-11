"""visibility-timeout-job-execution-timeout-expires."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visibility-timeout-job-execution-timeout-expires"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iot"]


# timing:real-time — workflow: 60 s
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A started (IN_PROGRESS) job execution that exceeds its executionTimeoutMinutes moves to the terminal
    TIMED_OUT state without the device reporting completion."""
    iot = ctx.client("iot")
    # iot:Data-ATS is the recommended endpoint type for Jobs/Commands (the
    # legacy iot:Jobs IPv4-only type is being retired in favor of it).
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint))

    # A thing is not a taggable IoT resource (TagResource on a :thing/ ARN
    # rejects with "Invalid resource type in ARN: thing"), so only the job
    # below carries a sim2real tag.
    thing_name = ctx.unique_name("sim2real-jobtimeoutthing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    job_id = ctx.unique_name("sim2real-jobtimeout-")
    # inProgressTimeoutInMinutes accepts a minimum of 1 minute, so the timeout
    # is observable within a short bounded poll.
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document='{"op":"noop"}',
        targetSelection="SNAPSHOT",
        timeoutConfig={"inProgressTimeoutInMinutes": 1},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_job(iot, job_id))

    # The job execution is created asynchronously after CreateJob; poll
    # DescribeJobExecution until it reaches QUEUED before the device claims it.
    deadline_queued = time.monotonic() + 30.0
    while time.monotonic() < deadline_queued:
        try:
            status = iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"]["status"]
        except ClientError:
            status = None
        if status == "QUEUED":
            break
        time.sleep(2.0)

    # The device claims and starts its queued execution -- this moves the
    # execution to IN_PROGRESS and starts the in-progress timer. The
    # execution may not be immediately claimable, so retry briefly.
    started = None
    deadline_start = time.monotonic() + 30.0
    while time.monotonic() < deadline_start:
        resp = jobs_data.start_next_pending_job_execution(thingName=thing_name)
        if "execution" in resp:
            started = resp
            break
        time.sleep(2.0)
    assert started is not None, "no pending job execution became claimable"
    started_status = started["execution"]["status"]
    assert started_status == "IN_PROGRESS", f"expected IN_PROGRESS, got {started_status}"

    # Deliberately never report completion; poll DescribeJobExecution until the
    # in-progress timer expires and the service auto-transitions the execution.
    deadline = time.monotonic() + 150.0
    final_status = None
    while time.monotonic() < deadline:
        execution = iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"]
        final_status = execution["status"]
        if final_status in ("TIMED_OUT", "SUCCEEDED", "FAILED", "REJECTED", "REMOVED", "CANCELED"):
            break
        time.sleep(5.0)

    assert final_status == "TIMED_OUT", f"expected TIMED_OUT, got {final_status}"


def _safe_delete_job(iot, job_id: str) -> None:
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
