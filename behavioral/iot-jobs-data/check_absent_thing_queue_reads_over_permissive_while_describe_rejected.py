"""absent-thing-queue-reads-over-permissive-while-describe-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "absent-thing-queue-reads-over-permissive-while-describe-rejected"
GROUP = 'over-permissive-not-found'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable only at the account-specific ATS host
# (data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation).
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
    """Poll fn() until predicate holds; CreateJob returns before the execution row is visible.

    Also tolerates a transient EndpointConnectionError while the just-resolved ATS host propagates.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = fn()
            if predicate(last):
                return last
        except (ClientError, EndpointConnectionError) as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed {last!r}"
            )
        time.sleep(interval_s)


def _all_thing_names(iot):
    """Every registry thing name, across all ListThings pages."""
    names = []
    token = None
    while True:
        page = iot.list_things(**({"nextToken": token} if token else {}))
        names.extend(t["thingName"] for t in page.get("things", []))
        token = page.get("nextToken")
        if not token:
            return names


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
    """For a thing absent from the registry, GetPendingJobExecutions and StartNextPendingJobExecution
    answer an empty 200, while Describe/UpdateJobExecution reject 404 "Job <id> not found for <thing>"
    whichever part is missing; the real thing's queued execution is left untouched.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-nf-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-jd-nfjob-")
    iot.create_job(jobId=job_id, targets=[thing_arn], document=json.dumps({"op": "noop"}))
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    # Positive control in the same file: the real pair resolves on every operation below.
    control = _poll(
        lambda: jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"],
        lambda e: e["status"] == "QUEUED",
        f"{job_id} queued for {thing}",
    )
    assert control["executionNumber"] == 1, (
        f"the first execution must be number 1, got {control['executionNumber']!r}"
    )
    assert any(
        j["jobId"] == job_id
        for j in jd.get_pending_job_executions(thingName=thing).get("queuedJobs", [])
    ), f"the control read must see {job_id} queued for {thing}"

    absent = ctx.unique_name("sim2real-behav-jd-ghost-")
    registry = _all_thing_names(iot)
    assert absent not in registry, (
        f"precondition: {absent!r} must not be in the registry, but ListThings returned it"
    )
    assert thing in registry, (
        f"precondition: the control thing {thing!r} must be in the registry; ListThings returned "
        f"{len(registry)} names"
    )

    empty_queue = jd.get_pending_job_executions(thingName=absent)
    assert empty_queue.get("queuedJobs", []) == [], (
        f"GetPendingJobExecutions on an absent thing must answer an empty queuedJobs, got "
        f"{empty_queue.get('queuedJobs')!r}"
    )
    assert empty_queue.get("inProgressJobs", []) == [], (
        f"GetPendingJobExecutions on an absent thing must answer an empty inProgressJobs, got "
        f"{empty_queue.get('inProgressJobs')!r}"
    )

    nothing_started = jd.start_next_pending_job_execution(thingName=absent)
    assert "execution" not in nothing_started, (
        f"StartNextPendingJobExecution on an absent thing must return no execution, got "
        f"{nothing_started.get('execution')!r}"
    )

    absent_thing_code, absent_thing_status, absent_thing_msg = _rejection(
        lambda: jd.describe_job_execution(thingName=absent, jobId=job_id)
    )
    assert absent_thing_code == "ResourceNotFoundException", (
        f"DescribeJobExecution on an absent thing must be rejected ResourceNotFoundException, got "
        f"{absent_thing_code!r}"
    )
    assert absent_thing_status == 404, f"expected HTTP 404, got {absent_thing_status!r}"
    assert absent_thing_msg == f"Job {job_id} not found for {absent}", (
        f"the message must name the job even though the THING is the missing part; got "
        f"{absent_thing_msg!r}"
    )

    write_code, write_status, write_msg = _rejection(
        lambda: jd.update_job_execution(thingName=absent, jobId=job_id, status="SUCCEEDED")
    )
    assert write_code == "ResourceNotFoundException", (
        f"UpdateJobExecution on an absent thing must be rejected ResourceNotFoundException, got "
        f"{write_code!r}"
    )
    assert write_status == 404, f"expected HTTP 404, got {write_status!r}"
    assert write_msg == f"Job {job_id} not found for {absent}", (
        f"unexpected absent-thing write message {write_msg!r}"
    )

    absent_job = ctx.unique_name("sim2real-behav-jd-nojob-")
    job_code, job_status, job_msg = _rejection(
        lambda: jd.describe_job_execution(thingName=thing, jobId=absent_job)
    )
    assert job_code == "ResourceNotFoundException", (
        f"an absent jobId must be rejected ResourceNotFoundException, got {job_code!r}"
    )
    assert job_status == 404, f"expected HTTP 404, got {job_status!r}"
    assert job_msg == f"Job {absent_job} not found for {thing}", (
        f"unexpected absent-job message {job_msg!r}"
    )

    num_code, num_status, num_msg = _rejection(
        lambda: jd.describe_job_execution(thingName=thing, jobId=job_id, executionNumber=99)
    )
    assert num_code == "ResourceNotFoundException", (
        f"an absent executionNumber must be rejected ResourceNotFoundException, got {num_code!r}"
    )
    assert num_status == 404, f"expected HTTP 404, got {num_status!r}"
    assert num_msg == f"Job {job_id} not found for {thing}", (
        f"the message must not mention the executionNumber that was actually wrong; got "
        f"{num_msg!r}"
    )

    # Effect absent: none of the rejected calls, and neither empty 200, touched the real execution.
    unchanged = jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert unchanged["status"] == "QUEUED", (
        f"the real execution must still be QUEUED, got {unchanged['status']!r}"
    )
    assert unchanged["versionNumber"] == control["versionNumber"], (
        f"the real execution's version must be unchanged at {control['versionNumber']!r}, got "
        f"{unchanged['versionNumber']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
