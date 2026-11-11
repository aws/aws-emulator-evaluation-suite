"""start-next-returns-in-progress-before-next-queued."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-next-returns-in-progress-before-next-queued"
GROUP = 'job-execution-queue'
SERVICES = ['iot-jobs-data']

# iot-jobs-data answers 403 "Invalid endpoint" at the host botocore resolves from its
# endpointPrefix; the reachable host is the account-specific `iot:Data-ATS` endpoint (AWS rejects
# the `iot:Jobs` endpoint type the model documents).
_QUEUE_TIMEOUT_S = 180.0
_QUEUE_INTERVAL_S = 2.0


def _jobs_data(ctx):
    """(iot control-plane client, iot-jobs-data client bound to this account's ATS host)."""
    iot = ctx.client("iot")
    host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return iot, ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(host))


def _poll(fn, predicate, what, timeout_s=_QUEUE_TIMEOUT_S, interval_s=_QUEUE_INTERVAL_S):
    """Poll fn() until predicate holds. Job-execution creation is asynchronous on real AWS:
    CreateJob returns before the per-target execution row is visible to the data plane."""
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartNextPendingJobExecution re-hands the IN_PROGRESS execution at an unchanged version,
    never the next QUEUED one, which becomes reachable only once the first is terminal: treating
    "next pending" as "next QUEUED" would double-dispatch work.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-queue-")
    iot.create_thing(thingName=thing)
    # IoT's TagResource rejects a thing ARN with InvalidRequestException ("Invalid resource
    # type in ARN: thing") and CreateThing has no tags param, so only the jobs below are tagged.
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    job_a = ctx.unique_name("sim2real-behav-jd-a-")
    iot.create_job(
        jobId=job_a, targets=[thing_arn], document=json.dumps({"op": "first"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_a))
    job_a_pending = _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: job_a in {j["jobId"] for j in r.get("queuedJobs", [])},
        f"{job_a} queued for {thing}",
    )
    job_a_queued_at = {j["jobId"]: j["queuedAt"] for j in job_a_pending["queuedJobs"]}[job_a]

    # queuedAt has second granularity: a tie would make "earliest queued" ambiguous and the
    # ordering assertion below unfair to a faithful emulator. Retry job_b's creation, bounded,
    # until AWS's OWN reported queuedAt actually separates the two — never a blind sleep on the
    # assumption that enough wall-clock time has passed.
    deadline = time.monotonic() + 30.0
    attempt = 0
    while True:
        attempt += 1
        job_b = ctx.unique_name(f"sim2real-behav-jd-b{attempt}-")
        iot.create_job(
            jobId=job_b, targets=[thing_arn], document=json.dumps({"op": "second"}),
            tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        job_b_pending = _poll(
            lambda: jd.get_pending_job_executions(thingName=thing),
            lambda r: job_b in {j["jobId"] for j in r.get("queuedJobs", [])},
            f"{job_b} queued for {thing}",
        )
        job_b_queued_at = {j["jobId"]: j["queuedAt"] for j in job_b_pending["queuedJobs"]}[job_b]
        if job_b_queued_at > job_a_queued_at:
            break
        _delete_job(iot, job_b)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after 30s trying to queue a job strictly after {job_a} "
                f"(queuedAt {job_a_queued_at!r}); every attempt tied its queuedAt"
            )
        time.sleep(1.0)
    ctx.on_cleanup(lambda: _delete_job(iot, job_b))

    pending = _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: {j["jobId"] for j in r.get("queuedJobs", [])} == {job_a, job_b},
        f"both {job_a} and {job_b} queued for {thing}",
    )
    queued_at = {j["jobId"]: j["queuedAt"] for j in pending["queuedJobs"]}
    assert queued_at[job_a] < queued_at[job_b], (
        f"precondition: {job_a} must be queued strictly before {job_b}, "
        f"got {queued_at[job_a]!r} and {queued_at[job_b]!r}"
    )
    assert pending.get("inProgressJobs", []) == [], (
        f"nothing has been started yet, so inProgressJobs must be empty, got "
        f"{pending.get('inProgressJobs')!r}"
    )

    first = jd.start_next_pending_job_execution(thingName=thing)["execution"]
    assert first["jobId"] == job_a, (
        f"the first StartNextPendingJobExecution must hand out the earlier-queued job {job_a}, "
        f"got {first['jobId']!r}"
    )
    assert first["status"] == "IN_PROGRESS", (
        f"a started execution must be IN_PROGRESS, got {first['status']!r}"
    )
    assert first["versionNumber"] == 2, (
        f"starting a QUEUED execution (version 1) must advance it to version 2, got "
        f"{first['versionNumber']!r}"
    )

    after_start = jd.get_pending_job_executions(thingName=thing)
    assert [j["jobId"] for j in after_start.get("inProgressJobs", [])] == [job_a], (
        f"inProgressJobs must hold exactly {job_a}, got {after_start.get('inProgressJobs')!r}"
    )
    assert [j["jobId"] for j in after_start.get("queuedJobs", [])] == [job_b], (
        f"queuedJobs must still hold exactly {job_b}, got {after_start.get('queuedJobs')!r}"
    )

    again = jd.start_next_pending_job_execution(thingName=thing)["execution"]
    assert again["jobId"] == job_a, (
        f"a second StartNextPendingJobExecution must re-hand the IN_PROGRESS execution {job_a}, "
        f"not start the next queued job; got {again['jobId']!r}"
    )
    assert again["versionNumber"] == first["versionNumber"], (
        f"re-handing an already-started execution must not advance its version: was "
        f"{first['versionNumber']!r}, now {again['versionNumber']!r}"
    )
    assert again["startedAt"] == first["startedAt"], (
        f"re-handing must not restamp startedAt: was {first['startedAt']!r}, now "
        f"{again['startedAt']!r}"
    )
    assert [j["jobId"] for j in jd.get_pending_job_executions(thingName=thing).get(
        "queuedJobs", []
    )] == [job_b], f"{job_b} must still be queued after the second start"

    jd.update_job_execution(
        thingName=thing, jobId=job_a, status="SUCCEEDED",
        expectedVersion=again["versionNumber"],
    )

    second = jd.start_next_pending_job_execution(thingName=thing)["execution"]
    assert second["jobId"] == job_b, (
        f"once {job_a} reached a terminal state the next start must hand out {job_b}, got "
        f"{second['jobId']!r}"
    )
    assert second["status"] == "IN_PROGRESS", (
        f"{job_b} must now be IN_PROGRESS, got {second['status']!r}"
    )

    final = jd.get_pending_job_executions(thingName=thing)
    assert [j["jobId"] for j in final.get("inProgressJobs", [])] == [job_b], (
        f"inProgressJobs must hold exactly {job_b}, got {final.get('inProgressJobs')!r}"
    )
    assert final.get("queuedJobs", []) == [], (
        f"both jobs have been dispatched, so queuedJobs must be empty, got "
        f"{final.get('queuedJobs')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
