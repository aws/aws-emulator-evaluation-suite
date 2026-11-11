"""terminal-execution-read-and-update-rejected-distinctly."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminal-execution-read-and-update-rejected-distinctly"
GROUP = 'terminal-state-rejected'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable ONLY at the account-specific ATS host (the regional
# data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation), and
# the endpoint type is `iot:Data-ATS` because `iot:Jobs` is retired.
_QUEUE_TIMEOUT_S = 180.0
_QUEUE_INTERVAL_S = 2.0


def _jobs_data(ctx):
    """(iot control-plane client, iot-jobs-data client bound to this account's ATS host)."""
    iot = ctx.client("iot")
    host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return iot, ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(host))


def _rejection(fn):
    """(error code, HTTP status, message) of the ClientError fn() raises; raises if fn SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message"),
        )
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


def _poll(fn, predicate, what, timeout_s=_QUEUE_TIMEOUT_S, interval_s=_QUEUE_INTERVAL_S):
    """Poll fn() until predicate holds; CreateJob returns before the execution row is visible."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = fn()
            if predicate(last):
                return last
        except ClientError as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed {last!r}"
            )
        time.sleep(interval_s)


def _delete_job(iot, job_id):
    """Undo CreateJob: a job with live executions must be cancelled before it can be deleted."""
    try:
        iot.cancel_job(jobId=job_id, force=True, comment="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    iot.delete_job(jobId=job_id, force=True)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A finished execution answers TerminalStateException 410 on read and 409 on write.

    After SUCCEEDED, DescribeJobExecution is TerminalStateException / 410, UpdateJobExecution is
    InvalidStateTransitionException / 409, and the refused write leaves the execution untouched.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-term-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-jd-termjob-")
    iot.create_job(jobId=job_id, targets=[thing_arn], document=json.dumps({"op": "reboot"}))
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: any(j["jobId"] == job_id for j in r.get("queuedJobs", [])),
        f"{job_id} queued for {thing}",
    )

    # Positive control, before the terminal state: BOTH operations succeed on this execution.
    started = jd.start_next_pending_job_execution(thingName=thing)["execution"]
    assert started["jobId"] == job_id, f"started the wrong job: {started['jobId']!r}"
    live_read = jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert live_read["status"] == "IN_PROGRESS", (
        f"the control read must see IN_PROGRESS, got {live_read['status']!r}"
    )
    mid = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="IN_PROGRESS",
        expectedVersion=live_read["versionNumber"], includeJobExecutionState=True,
    )["executionState"]
    assert mid["status"] == "IN_PROGRESS", (
        f"the control write must be accepted; got {mid['status']!r}"
    )

    finished = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="SUCCEEDED",
        expectedVersion=mid["versionNumber"], includeJobExecutionState=True,
    )["executionState"]
    assert finished["status"] == "SUCCEEDED", (
        f"the execution must reach SUCCEEDED; got {finished['status']!r}"
    )
    terminal_version = finished["versionNumber"]

    read_code, read_status, read_msg = _rejection(
        lambda: jd.describe_job_execution(thingName=thing, jobId=job_id)
    )
    assert read_code == "TerminalStateException", (
        f"reading a finished execution must be rejected TerminalStateException, got {read_code!r}"
    )
    assert read_status == 410, (
        f"TerminalStateException is an HTTP 410 Gone, got {read_status!r}"
    )
    assert read_msg == (
        "Job Execution has reached terminal state. It is neither IN_PROGRESS nor QUEUED"
    ), f"unexpected terminal-read message {read_msg!r}"

    write_code, write_status, write_msg = _rejection(
        lambda: jd.update_job_execution(thingName=thing, jobId=job_id, status="FAILED")
    )
    assert write_code == "InvalidStateTransitionException", (
        f"writing a finished execution must be rejected InvalidStateTransitionException, got "
        f"{write_code!r}"
    )
    assert write_status == 409, (
        f"InvalidStateTransitionException is an HTTP 409, got {write_status!r}"
    )
    assert write_msg == (
        f"Job {job_id} for {thing} has already finished with status SUCCEEDED"
    ), f"unexpected terminal-write message {write_msg!r}"

    # Effect absent: the refused write neither reopened the execution nor moved its version. The
    # data plane can no longer read a terminal execution at all, so the control plane is the reader.
    after = iot.describe_job_execution(jobId=job_id, thingName=thing)["execution"]
    assert after["status"] == "SUCCEEDED", (
        f"the refused write must leave the execution SUCCEEDED, got {after['status']!r}"
    )
    assert after["versionNumber"] == terminal_version, (
        f"a refused write must not advance the version: was {terminal_version!r}, now "
        f"{after['versionNumber']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
