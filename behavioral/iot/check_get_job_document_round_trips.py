"""get-job-document-round-trips."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-job-document-round-trips"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _delete_job(iot, job_id):
    """Teardown: cancel then force-delete a job; only a missing or already-terminal job is tolerated."""
    try:
        iot.cancel_job(jobId=job_id, force=True)
    except ClientError as exc:
        # An already-terminal job needs no cancel; the delete below still runs.
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidStateTransitionException"):
            raise
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetJobDocument returns the exact document supplied to CreateJob."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-jobdoc-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    document = json.dumps({"operation": "install", "package": "probe", "version": "1.2.3"})
    job_id = ctx.unique_name("sim2real-behav-job-doc-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=document,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _j=job_id: _delete_job(iot, _j))

    got = iot.get_job_document(jobId=job_id)["document"]
    assert json.loads(got) == json.loads(document), f"document must round-trip, got {got}"

    job = iot.describe_job(jobId=job_id)["job"]
    assert job["jobId"] == job_id, f"expected jobId {job_id}, got {job.get('jobId')}"
    assert job["targets"] == [thing_arn], job["targets"]
    # A job targeting a single thing defaults to SNAPSHOT (not CONTINUOUS).
    assert job.get("targetSelection") == "SNAPSHOT", job.get("targetSelection")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
