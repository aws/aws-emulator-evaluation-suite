"""include-toggles-have-opposite-defaults-per-operation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "include-toggles-have-opposite-defaults-per-operation"
GROUP = 'payload-toggles'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable ONLY at the account-specific ATS host (the regional
# data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation), and
# the endpoint type is `iot:Data-ATS` because `iot:Jobs` is retired.
_QUEUE_TIMEOUT_S = 180.0
_QUEUE_INTERVAL_S = 2.0
_DOCUMENT = {"op": "install", "url": "s3://sim2real/pkg.bin"}


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


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """includeJobDocument defaults ON for DescribeJobExecution and OFF for UpdateJobExecution.

    DescribeJobExecution drops `jobDocument` only for an explicit `false`; UpdateJobExecution
    returns an empty body with both flags omitted, and each flag adds exactly its own member.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-toggle-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-jd-togjob-")
    iot.create_job(
        jobId=job_id, targets=[thing_arn], document=json.dumps(_DOCUMENT),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    default_read = _poll(
        lambda: jd.describe_job_execution(thingName=thing, jobId=job_id)["execution"],
        lambda e: e["status"] == "QUEUED",
        f"{job_id} queued for {thing}",
    )
    assert json.loads(default_read["jobDocument"]) == _DOCUMENT, (
        f"DescribeJobExecution must return the job document when includeJobDocument is OMITTED; "
        f"got {default_read.get('jobDocument')!r}"
    )

    off_read = jd.describe_job_execution(
        thingName=thing, jobId=job_id, includeJobDocument=False
    )["execution"]
    assert "jobDocument" not in off_read, (
        f"includeJobDocument=false must drop the document; got {off_read.get('jobDocument')!r}"
    )
    assert off_read["status"] == "QUEUED" and off_read["versionNumber"] == 1, (
        f"dropping the document must not change the rest of the record; got {off_read!r}"
    )

    jd.start_next_pending_job_execution(thingName=thing)

    bare = jd.update_job_execution(thingName=thing, jobId=job_id, status="IN_PROGRESS")
    assert "executionState" not in bare, (
        f"UpdateJobExecution with no toggles must return no executionState; got "
        f"{bare.get('executionState')!r}"
    )
    assert "jobDocument" not in bare, (
        f"UpdateJobExecution with no toggles must return no jobDocument; got "
        f"{bare.get('jobDocument')!r}"
    )

    state_only = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="IN_PROGRESS", includeJobExecutionState=True
    )
    assert state_only["executionState"]["status"] == "IN_PROGRESS", (
        f"includeJobExecutionState=true must return the state; got "
        f"{state_only.get('executionState')!r}"
    )
    assert "jobDocument" not in state_only, (
        f"includeJobExecutionState must not also return the document; got "
        f"{state_only.get('jobDocument')!r}"
    )

    doc_only = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="IN_PROGRESS", includeJobDocument=True
    )
    assert json.loads(doc_only["jobDocument"]) == _DOCUMENT, (
        f"includeJobDocument=true must return the document; got {doc_only.get('jobDocument')!r}"
    )
    assert "executionState" not in doc_only, (
        f"includeJobDocument must not also return the state; got "
        f"{doc_only.get('executionState')!r}"
    )

    both = jd.update_job_execution(
        thingName=thing, jobId=job_id, status="SUCCEEDED",
        includeJobExecutionState=True, includeJobDocument=True,
    )
    assert both["executionState"]["status"] == "SUCCEEDED", (
        f"both toggles must still return the state; got {both.get('executionState')!r}"
    )
    assert json.loads(both["jobDocument"]) == _DOCUMENT, (
        f"both toggles must still return the document; got {both.get('jobDocument')!r}"
    )

    # The last update's effect must be observable off an independent read, not only in its own echo.
    # The jobs-data DescribeJobExecution refuses a terminal execution, so the independent read that
    # can actually reach a SUCCEEDED execution is the control plane's own DescribeJobExecution.
    control_read = iot.describe_job_execution(thingName=thing, jobId=job_id)["execution"]
    assert control_read["status"] == "SUCCEEDED", (
        f"the control plane must agree the final status persisted as SUCCEEDED; got "
        f"{control_read.get('status')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
