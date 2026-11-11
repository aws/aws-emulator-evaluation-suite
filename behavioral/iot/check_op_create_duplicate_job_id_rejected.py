"""op-create-duplicate-job-id-rejected."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-create-duplicate-job-id-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    success raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

def _delete_job(iot, job_id):
    """Teardown: DeleteJob with force=True removes a job in any state, so no cancel is needed."""
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-using an existing jobId in CreateJob must conflict, not silently replace the job."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-dupjob-")
    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": CHECK}})
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-job-dup-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=json.dumps({"operation": "first"}),
        description="original",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=job_id: _delete_job(iot, _n))

    code, message = _err(
        lambda: iot.create_job(
            jobId=job_id,
            targets=[thing_arn],
            document=json.dumps({"operation": "second"}),
            description="replacement",
        )
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException, got {code}"
    )
    assert message == f"Job {job_id} already exists.", message

    # the original job must be intact -- the rejected duplicate must not have replaced it
    desc = iot.describe_job(jobId=job_id)
    actual_description = desc["job"]["description"]
    assert actual_description == "original", (
        f"expected the original job's description to survive the rejected duplicate "
        f"create unchanged ('original'), got {actual_description!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
