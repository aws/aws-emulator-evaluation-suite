"""jobs-data-step-timeout-times-out-one-thing-while-a-reset-twin-survives."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "jobs-data-step-timeout-times-out-one-thing-while-a-reset-twin-survives"
GROUP = "state-machine"
SERVICES = ["iot"]

_SUBJECT_STEP_MINUTES = 1
_TWIN_STEP_MINUTES = 10
_TIMEOUT_DEADLINE_S = 240.0
_TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "REJECTED", "REMOVED", "CANCELED"}


# timing:real-time — workflow: 60 s
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A jobs-data step timeout expires one execution while a reset twin on the same job survives.

    Both things start with a 1-minute step timeout and the twin resets its timer to 10 minutes; when
    the silent subject reaches TIMED_OUT, the twin must still be IN_PROGRESS.
    """
    iot = ctx.client("iot")
    # iot-jobs-data is not reachable at botocore's default endpointPrefix host; real AWS answers
    # every operation there with 403 AccessDeniedException "Invalid endpoint. Use describe-endpoint
    # API to get valid endpoint". The reachable host is the account-specific iot:Data-ATS endpoint.
    jobs_host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(jobs_host))

    tags_kv = [{"Key": "sim2real", "Value": "jobs-data-step-timeout"}]

    subject = ctx.unique_name("sim2real-iot-stepsubj-")
    twin = ctx.unique_name("sim2real-iot-steptwin-")
    arns = {}
    for name in (subject, twin):
        created = iot.create_thing(thingName=name)
        arns[name] = created["thingArn"]
        ctx.on_cleanup(lambda n=name: iot.delete_thing(thingName=n))

    job_id = ctx.unique_name("sim2real-iot-stepjob-")
    iot.create_job(
        jobId=job_id,
        targets=[arns[subject], arns[twin]],
        document=json.dumps({"operation": "sim2real-noop", "marker": job_id}),
        targetSelection="SNAPSHOT",
        # Deliberately NO timeoutConfig: any TIMED_OUT below can then only come from the step timer.
        tags=tags_kv,
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    for name in (subject, twin):
        _poll_until(
            lambda n=name: jobs.get_pending_job_executions(thingName=n),
            lambda resp: any(e["jobId"] == job_id for e in resp.get("queuedJobs", [])),
            timeout_s=90.0,
            what=f"the SNAPSHOT job {job_id!r} never appeared as a queued execution for {name!r}",
        )

    started = {}
    for name in (subject, twin):
        resp = jobs.start_next_pending_job_execution(
            thingName=name, stepTimeoutInMinutes=_SUBJECT_STEP_MINUTES)
        execution = resp["execution"]
        assert execution["jobId"] == job_id, (
            f"StartNextPendingJobExecution for {name!r} returned job "
            f"{execution.get('jobId')!r}, expected the only queued job {job_id!r}"
        )
        assert execution["status"] == "IN_PROGRESS", (
            f"StartNextPendingJobExecution left {name!r} in status "
            f"{execution.get('status')!r}, expected 'IN_PROGRESS'"
        )
        started[name] = execution

    # ---- THE TWIN CONTROL, armed in the same instant: reset the twin's timer to 10 minutes.
    reset = jobs.update_job_execution(
        jobId=job_id,
        thingName=twin,
        status="IN_PROGRESS",
        stepTimeoutInMinutes=_TWIN_STEP_MINUTES,
        expectedVersion=started[twin]["versionNumber"],
        includeJobExecutionState=True,
    )
    reset_state = reset["executionState"]
    assert reset_state["status"] == "IN_PROGRESS", (
        f"resetting the twin's step timer left it in status {reset_state.get('status')!r}, "
        "expected 'IN_PROGRESS'"
    )
    assert reset_state["versionNumber"] > started[twin]["versionNumber"], (
        "the twin's execution version did not advance across the reset: it was "
        f"{started[twin]['versionNumber']!r} and is now {reset_state.get('versionNumber')!r}; "
        "without an advancing version the reset cannot be distinguished from a no-op"
    )

    # ---- The subject stays silent and must expire. Terminal read on the CONTROL plane, through a
    # different operation and a different service from the jobs-data calls that armed the timer.
    final = _poll_until(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=subject)["execution"],
        lambda ex: ex["status"] in _TERMINAL,
        timeout_s=_TIMEOUT_DEADLINE_S,
        what=(
            f"the subject execution for {subject!r} never left IN_PROGRESS within "
            f"{_TIMEOUT_DEADLINE_S}s of arming a {_SUBJECT_STEP_MINUTES}-minute step timeout"
        ),
    )
    assert final["status"] == "TIMED_OUT", (
        f"the silent subject execution ended in {final['status']!r}, expected 'TIMED_OUT' from the "
        f"{_SUBJECT_STEP_MINUTES}-minute step timer (the job carries no timeoutConfig, so no other "
        "timer could have moved it)"
    )

    # ---- The twin, read at the SAME moment, must be untouched.
    twin_execution = iot.describe_job_execution(jobId=job_id, thingName=twin)["execution"]
    assert twin_execution["status"] == "IN_PROGRESS", (
        f"the twin execution for {twin!r} was {twin_execution['status']!r} at the instant the "
        f"subject reached TIMED_OUT, expected 'IN_PROGRESS': its step timer was reset to "
        f"{_TWIN_STEP_MINUTES} minutes, so a target that expires every in-progress execution on one "
        "schedule is what this assertion catches"
    )

    # ---- The job's own aggregate view must agree with both per-execution reads.
    details = _poll_until(
        lambda: iot.describe_job(jobId=job_id)["job"]["jobProcessDetails"],
        lambda d: d.get("numberOfTimedOutThings") == 1,
        timeout_s=90.0,
        what=(
            f"describe_job for {job_id!r} never reported numberOfTimedOutThings == 1 even though "
            "the subject execution reads as TIMED_OUT"
        ),
    )
    assert details["numberOfTimedOutThings"] == 1, (
        f"jobProcessDetails reported numberOfTimedOutThings="
        f"{details.get('numberOfTimedOutThings')!r}, expected 1"
    )
    assert details["numberOfInProgressThings"] == 1, (
        f"jobProcessDetails reported numberOfInProgressThings="
        f"{details.get('numberOfInProgressThings')!r}, expected 1 — the reset twin"
    )

    # ---- The jobs data plane's own DescribeJobExecution is modelled with a TerminalStateException
    # (HTTP 410): a device may consult it only while its execution is QUEUED or IN_PROGRESS, and it
    # refuses once terminal rather than echoing the control plane's TIMED_OUT. The positive control
    # is the SAME operation, at the SAME moment, on the non-terminal twin: it must still succeed.
    from botocore.exceptions import ClientError
    twin_dp_view = jobs.describe_job_execution(jobId=job_id, thingName=twin)["execution"]
    assert twin_dp_view["status"] == "IN_PROGRESS", (
        f"the jobs data plane's DescribeJobExecution for the non-terminal twin {twin!r} reported "
        f"{twin_dp_view.get('status')!r}, expected 'IN_PROGRESS' -- the positive control for the "
        "refusal asserted next"
    )
    try:
        jobs.describe_job_execution(jobId=job_id, thingName=subject)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        http_status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        message = err.response["Error"]["Message"]
        assert code == "TerminalStateException", (
            f"the jobs data plane's DescribeJobExecution for the TIMED_OUT execution of {subject!r} "
            f"failed with {code!r}, expected 'TerminalStateException'"
        )
        assert http_status == 410, (
            f"TerminalStateException is documented as HTTP 410 Gone, got {http_status!r}"
        )
        assert message == (
            "Job Execution has reached terminal state. It is neither IN_PROGRESS nor QUEUED"
        ), f"unexpected terminal-read message for a TIMED_OUT execution: {message!r}"
    else:
        raise AssertionError(
            f"the jobs data plane's DescribeJobExecution returned a result for the TIMED_OUT "
            f"execution of {subject!r}; expected a TerminalStateException refusal (HTTP 410) since "
            "the same operation just succeeded for the non-terminal twin"
        )
    try:
        jobs.update_job_execution(jobId=job_id, thingName=subject, status="SUCCEEDED")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "InvalidStateTransitionException", (
            f"updating a TIMED_OUT execution failed with {code!r} ({message!r}); "
            "expected 'InvalidStateTransitionException'"
        )
        expected = f"Job {job_id} for {subject} has already finished with status TIMED_OUT"
        assert message == expected, f"UpdateJobExecution message {message!r} != {expected!r}"
    else:
        raise AssertionError(
            f"UpdateJobExecution moved the TIMED_OUT execution for {subject!r} to SUCCEEDED; "
            "TIMED_OUT is terminal and the device must not be able to resurrect it"
        )
    after = iot.describe_job_execution(jobId=job_id, thingName=subject)["execution"]
    assert after["status"] == "TIMED_OUT", (
        f"the refused update still changed the execution's status to {after.get('status')!r}, "
        "expected it to remain 'TIMED_OUT'"
    )


def _poll_until(probe, predicate, *, timeout_s: float, what: str, interval_s: float = 3.0):
    """Bounded retry with a stated reason; RAISES on timeout rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}; last observation was {last!r} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
