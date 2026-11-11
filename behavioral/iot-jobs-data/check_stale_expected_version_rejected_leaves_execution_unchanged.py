"""stale-expected-version-rejected-leaves-execution-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stale-expected-version-rejected-leaves-execution-unchanged"
GROUP = 'optimistic-concurrency-rejected'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable ONLY at the account-specific ATS host; the regionally-resolved
# data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation.
# `iot:Jobs` is retired (InvalidRequestException), so the endpoint type is `iot:Data-ATS`.
_QUEUE_TIMEOUT_S = 180.0
_QUEUE_INTERVAL_S = 2.0


def _jobs_data(ctx):
    """(iot control-plane client, iot-jobs-data client bound to this account's ATS host)."""
    iot = ctx.client("iot")
    host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return iot, ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(host))


def _rejection(fn):
    """(error code, HTTP status, message) of the ClientError fn() raises.

    Raises AssertionError when fn() SUCCEEDS: an emulator accepting input real AWS rejects is the
    strongest signal available, and returning a falsy sentinel here would disguise it as an
    error-code mismatch.
    """
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
    """A mismatched expectedVersion is rejected and leaves the execution byte-identical.

    A past or future version is InvalidRequestException / HTTP 400 naming both versions, status,
    versionNumber and statusDetails are untouched, and the correct version is then still accepted.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-ver-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-jd-verjob-")
    iot.create_job(
        jobId=job_id, targets=[thing_arn], document=json.dumps({"op": "flash"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    _poll(
        lambda: jd.get_pending_job_executions(thingName=thing),
        lambda r: any(j["jobId"] == job_id for j in r.get("queuedJobs", [])),
        f"{job_id} queued for {thing}",
    )

    started = jd.start_next_pending_job_execution(
        thingName=thing, statusDetails={"phase": "download"}
    )["execution"]
    live = started["versionNumber"]
    assert live == 2, f"a started execution must be at version 2, got {live!r}"

    stale_code, stale_status, stale_msg = _rejection(
        lambda: jd.update_job_execution(
            thingName=thing, jobId=job_id, status="SUCCEEDED", expectedVersion=live - 1
        )
    )
    assert stale_code == "InvalidRequestException", (
        f"a stale expectedVersion must be rejected InvalidRequestException, got {stale_code!r}"
    )
    assert stale_status == 400, (
        f"the version guard is a 400, not a conflict status, got {stale_status!r}"
    )
    assert stale_msg == f"Expected version {live - 1} but found version {live}", (
        f"unexpected version-conflict message {stale_msg!r}"
    )

    unchanged = jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert unchanged["status"] == "IN_PROGRESS", (
        f"the refused update must not change status; got {unchanged['status']!r}"
    )
    assert unchanged["versionNumber"] == live, (
        f"a refused update must not advance the version: was {live!r}, now "
        f"{unchanged['versionNumber']!r}"
    )
    assert unchanged.get("statusDetails") == {"phase": "download"}, (
        f"the refused update must not touch statusDetails; got "
        f"{unchanged.get('statusDetails')!r}"
    )

    future_code, future_status, future_msg = _rejection(
        lambda: jd.update_job_execution(
            thingName=thing, jobId=job_id, status="SUCCEEDED", expectedVersion=live + 5
        )
    )
    assert future_code == "InvalidRequestException", (
        f"a future expectedVersion must also be rejected InvalidRequestException, got "
        f"{future_code!r}"
    )
    assert future_status == 400, f"expected HTTP 400, got {future_status!r}"
    assert future_msg == f"Expected version {live + 5} but found version {live}", (
        f"the guard must be an EXACT match, not a floor; got {future_msg!r}"
    )
    still = jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert still["versionNumber"] == live, (
        f"two refusals must leave the version at {live!r}, got {still['versionNumber']!r}"
    )

    # Positive control in the same file: the CORRECT version is accepted and advances by one.
    accepted = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="SUCCEEDED", expectedVersion=live,
        includeJobExecutionState=True,
    )["executionState"]
    assert accepted["status"] == "SUCCEEDED", (
        f"the control update must be accepted; got {accepted['status']!r}"
    )
    assert accepted["versionNumber"] == live + 1, (
        f"an accepted update must advance the version by exactly 1 to {live + 1}, got "
        f"{accepted['versionNumber']!r}"
    )

    # Independent terminal read, at the control plane, on a different operation than the one
    # that mutated: the accepted write must be durable, not just echoed in its own response.
    control = iot.describe_job_execution(jobId=job_id, thingName=thing)["execution"]
    assert control["status"] == "SUCCEEDED", (
        f"the control plane must agree the accepted update landed; got {control['status']!r}"
    )
    assert control["versionNumber"] == live + 1, (
        f"the control plane must report the same advanced version {live + 1}, got "
        f"{control['versionNumber']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
