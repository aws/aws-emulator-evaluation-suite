"""illegal-status-transitions-rejected-queued-to-succeeded-allowed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "illegal-status-transitions-rejected-queued-to-succeeded-allowed"
GROUP = 'state-machine-rejected'
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


def _wait_for_new_second(after_s, timeout_s=10.0, interval_s=0.2):
    """Block until the wall clock reads a whole second later than after_s (a POSIX timestamp).

    queuedAt has whole-second granularity, so two executions whose queuedAt values land in
    the same second would tie the sort key, making "the earlier-queued job" ambiguous and the
    ordering assertion below unfair to a faithful emulator. CreateJob's own return is NOT a
    proxy for queuedAt — job-execution creation is asynchronous, so the caller must pass
    job_a's REAL, observed queuedAt (read back via GetPendingJobExecutions), never the local
    time CreateJob was called.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        if int(time.time()) > int(after_s):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for the wall clock to advance past "
                f"the second job_a was queued in"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The illegal transitions are the BACKWARD ones — skipping IN_PROGRESS is legal.

    From IN_PROGRESS, QUEUED and REJECTED are InvalidStateTransitionException / HTTP 409 with the
    execution unchanged, while QUEUED -> SUCCEEDED directly is accepted.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-trans-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_a = ctx.unique_name("sim2real-behav-jd-transa-")
    iot.create_job(
        jobId=job_a, targets=[thing_arn], document=json.dumps({"op": "a"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_a))

    queued_a = _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: any(j["jobId"] == job_a for j in r.get("queuedJobs", [])),
        f"{job_a} queued for {thing}",
    )
    job_a_queued_at = next(
        j["queuedAt"] for j in queued_a["queuedJobs"] if j["jobId"] == job_a
    )
    _wait_for_new_second(job_a_queued_at)

    job_b = ctx.unique_name("sim2real-behav-jd-transb-")
    iot.create_job(
        jobId=job_b, targets=[thing_arn], document=json.dumps({"op": "b"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_b))

    _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: {j["jobId"] for j in r.get("queuedJobs", [])} == {job_a, job_b},
        f"both {job_a} and {job_b} queued for {thing}",
    )

    started = jd.start_next_pending_job_execution(thingName=thing)["execution"]
    assert started["jobId"] == job_a, (
        f"the earlier-queued job {job_a} must be the one started, got {started['jobId']!r}"
    )
    live = started["versionNumber"]

    rewind_code, rewind_status, rewind_msg = _rejection(
        lambda: jd.update_job_execution(
            thingName=thing, jobId=job_a, status="QUEUED", expectedVersion=live
        )
    )
    assert rewind_code == "InvalidStateTransitionException", (
        f"IN_PROGRESS -> QUEUED must be rejected InvalidStateTransitionException, got "
        f"{rewind_code!r}"
    )
    assert rewind_status == 409, f"expected HTTP 409, got {rewind_status!r}"
    assert rewind_msg == "The status of job execution cannot be changed to be QUEUED", (
        f"unexpected rewind message {rewind_msg!r}"
    )
    after_rewind = jd.describe_job_execution(thingName=thing, jobId=job_a)["execution"]
    assert after_rewind["status"] == "IN_PROGRESS", (
        f"the refused rewind must leave the execution IN_PROGRESS, got "
        f"{after_rewind['status']!r}"
    )
    assert after_rewind["versionNumber"] == live, (
        f"a refused transition must not advance the version: was {live!r}, now "
        f"{after_rewind['versionNumber']!r}"
    )

    reject_code, reject_status, reject_msg = _rejection(
        lambda: jd.update_job_execution(
            thingName=thing, jobId=job_a, status="REJECTED", expectedVersion=live
        )
    )
    assert reject_code == "InvalidStateTransitionException", (
        f"IN_PROGRESS -> REJECTED must be rejected InvalidStateTransitionException, got "
        f"{reject_code!r}"
    )
    assert reject_status == 409, f"expected HTTP 409, got {reject_status!r}"
    assert reject_msg == "Only queued jobs can be rejected. Job was in status IN_PROGRESS", (
        f"unexpected reject-transition message {reject_msg!r}"
    )
    after_reject = jd.describe_job_execution(thingName=thing, jobId=job_a)["execution"]
    assert after_reject["versionNumber"] == live, (
        f"two refusals must leave the version at {live!r}, got "
        f"{after_reject['versionNumber']!r}"
    )

    # Positive control in the same file: the QUEUED execution goes straight to SUCCEEDED.
    queued = jd.describe_job_execution(thingName=thing, jobId=job_b)["execution"]
    assert queued["status"] == "QUEUED", (
        f"{job_b} must still be QUEUED, got {queued['status']!r}"
    )
    skipped = jd.update_job_execution(
        thingName=thing, jobId=job_b, status="SUCCEEDED",
        expectedVersion=queued["versionNumber"], includeJobExecutionState=True,
    )["executionState"]
    assert skipped["status"] == "SUCCEEDED", (
        f"QUEUED -> SUCCEEDED must be accepted without an intervening IN_PROGRESS, got "
        f"{skipped['status']!r}"
    )
    assert skipped["versionNumber"] == queued["versionNumber"] + 1, (
        f"the accepted transition must advance the version by exactly 1 to "
        f"{queued['versionNumber'] + 1}, got {skipped['versionNumber']!r}"
    )

    # Independent read at the destination: do not terminate on UpdateJobExecution's own response.
    # The data-plane DescribeJobExecution refuses a terminal execution — the control plane's own
    # DescribeJobExecution is the reader once a job execution is finished.
    final = iot.describe_job_execution(jobId=job_b, thingName=thing)["execution"]
    assert final["status"] == "SUCCEEDED", (
        f"an independent read of {job_b} must confirm SUCCEEDED, got {final['status']!r}"
    )
    assert final["versionNumber"] == skipped["versionNumber"], (
        f"the independent read must agree on versionNumber {skipped['versionNumber']!r}, got "
        f"{final['versionNumber']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
