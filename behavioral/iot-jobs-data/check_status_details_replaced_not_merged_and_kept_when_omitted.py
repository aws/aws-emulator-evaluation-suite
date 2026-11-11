"""status-details-replaced-not-merged-and-kept-when-omitted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "status-details-replaced-not-merged-and-kept-when-omitted"
GROUP = 'status-details'
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """statusDetails is REPLACED when supplied and PRESERVED when omitted.

    A write carrying `{"stage": "verify"}` over `{"stage": "download", "attempt": "1"}` leaves only
    `{"stage": "verify"}`, and a later write that omits statusDetails keeps that map.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-details-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-jd-detjob-")
    iot.create_job(jobId=job_id, targets=[thing_arn], document=json.dumps({"op": "install"}))
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    queued = _poll(
        lambda: jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"],
        lambda e: e["status"] == "QUEUED",
        f"{job_id} queued for {thing}",
    )
    assert "statusDetails" not in queued, (
        f"a freshly queued execution must carry no statusDetails at all, got "
        f"{queued.get('statusDetails')!r}"
    )

    started = jd.start_next_pending_job_execution(
        thingName=thing, statusDetails={"stage": "download", "attempt": "1"}
    )["execution"]
    assert started["statusDetails"] == {"stage": "download", "attempt": "1"}, (
        f"StartNextPendingJobExecution must store the statusDetails it was handed, got "
        f"{started.get('statusDetails')!r}"
    )
    v_start = started["versionNumber"]

    replaced = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="IN_PROGRESS",
        statusDetails={"stage": "verify"}, expectedVersion=v_start,
        includeJobExecutionState=True,
    )["executionState"]
    assert replaced["statusDetails"] == {"stage": "verify"}, (
        f"a supplied statusDetails must REPLACE the stored map (dropping 'attempt'), got "
        f"{replaced.get('statusDetails')!r}"
    )
    assert replaced["versionNumber"] == v_start + 1, (
        f"an accepted update must advance the version by exactly 1 to {v_start + 1}, got "
        f"{replaced['versionNumber']!r}"
    )
    # The write is observable off the response too, not only in it.
    reread = jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert reread["statusDetails"] == {"stage": "verify"}, (
        f"DescribeJobExecution must agree with the update response, got "
        f"{reread.get('statusDetails')!r}"
    )

    kept = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="SUCCEEDED",
        expectedVersion=replaced["versionNumber"], includeJobExecutionState=True,
    )["executionState"]
    assert kept["status"] == "SUCCEEDED", (
        f"the final update must be accepted; got {kept['status']!r}"
    )
    assert kept["statusDetails"] == {"stage": "verify"}, (
        f"omitting statusDetails must PRESERVE the stored map, not clear it; got "
        f"{kept.get('statusDetails')!r}"
    )
    assert kept["versionNumber"] == replaced["versionNumber"] + 1, (
        f"the third accepted write must reach version {replaced['versionNumber'] + 1}, got "
        f"{kept['versionNumber']!r}"
    )

    # The iot control plane's DescribeJobExecution returns the same map nested under a detailsMap key.
    control = iot.describe_job_execution(jobId=job_id, thingName=thing)["execution"]
    assert control["statusDetails"] == {"detailsMap": {"stage": "verify"}}, (
        f"the iot control plane must report the same map under a detailsMap wrapper, got "
        f"{control.get('statusDetails')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
