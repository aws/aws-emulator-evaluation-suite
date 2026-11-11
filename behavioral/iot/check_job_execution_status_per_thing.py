"""job-execution-status-per-thing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-execution-status-per-thing"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

def _delete_job(iot, job_id):
    """Teardown: DeleteJob with force=True removes a job in any state, so no cancel is needed."""
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeJobExecution reports a per-target execution record queued for the job's
    thing, and no execution record exists for a thing the job does not target."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-jobexec-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    other_thing = ctx.unique_name("sim2real-behav-thing-jobexec-other-")
    iot.create_thing(thingName=other_thing)
    ctx.on_cleanup(lambda _n=other_thing: iot.delete_thing(thingName=_n))

    job_id = ctx.unique_name("sim2real-behav-job-exec-")
    iot.create_job(
        jobId=job_id, targets=[thing_arn], document=json.dumps({"operation": "noop"})
    )
    ctx.on_cleanup(lambda _n=job_id: _delete_job(iot, _n))

    execution = _eventually(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=thing),
        lambda e: e["execution"]["status"] in ("QUEUED", "IN_PROGRESS"),
        timeout_s=90,
        interval_s=3,
    )
    assert execution["execution"]["status"] in ("QUEUED", "IN_PROGRESS")
    assert execution["execution"]["jobId"] == job_id

    listed = _eventually(
        lambda: iot.list_job_executions_for_thing(thingName=thing).get(
            "executionSummaries", []
        ),
        lambda summaries: any(e["jobId"] == job_id for e in summaries),
        timeout_s=90,
        interval_s=3,
    )
    assert any(e["jobId"] == job_id for e in listed), listed

    # The job's target list excludes other_thing, so its per-thing execution record
    # must never come into existence — this is the "per thing" contract under test.
    try:
        iot.describe_job_execution(jobId=job_id, thingName=other_thing)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for untargeted thing, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected = f"Job execution for thing {other_thing} cannot be found within job {job_id}."
        assert message == expected, f"DescribeJobExecution message {message!r} != {expected!r}"
    else:
        raise AssertionError(
            f"expected ResourceNotFoundException: job {job_id} has no execution "
            f"targeting {other_thing}, but DescribeJobExecution returned one"
        )

    other_listed = iot.list_job_executions_for_thing(thingName=other_thing).get(
        "executionSummaries", []
    )
    assert not any(e["jobId"] == job_id for e in other_listed), other_listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
