"""batch-stop-job-run-rejects-a-succeeded-run-but-stops-a-running-one."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-stop-job-run-rejects-a-succeeded-run-but-stops-a-running-one"
GROUP = "job-run-stop"
SERVICES = ["glue", "iam", "s3"]

_STOP_REJECTED = (
    "JobRunCannotBeStoppedException",
    "Job Run cannot be stopped in current state.",
)

_TERMINAL_STATES = {"STOPPED", "SUCCEEDED", "FAILED", "TIMEOUT", "ERROR", "EXPIRED"}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"no match within {timeout_s}s; last observed value was {last!r}")


def _start_job_run(glue, job: str, *, deadline_s: float = 60.0):
    """StartJobRun, retrying while the job's previous run has not yet freed its concurrency slot."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return glue.start_job_run(JobName=job)["JobRunId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ConcurrentRunsExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _run_to_terminal(glue, job: str, *, timeout_s: float = 90.0):
    """StartJobRun on `job`, then poll GetJobRun to a terminal state."""
    run_id = _start_job_run(glue, job)
    state = _poll_until(
        lambda: glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]["JobRunState"],
        lambda s: s in _TERMINAL_STATES,
        timeout_s=timeout_s,
    )
    return run_id, state


def _run_until_role_is_assumable(glue, job: str, *, deadline_s: float = 150.0):
    """Re-runs `job` while a role IAM has not yet propagated makes Glue's own AssumeRole
    check reject it; no API reports propagation, so a failed first use is the only signal.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        run_id, state = _run_to_terminal(glue, job)
        if state != "FAILED":
            return run_id, state
        detail = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"].get("ErrorMessage") or ""
        if "assume role" not in detail.lower() or time.monotonic() >= deadline:
            return run_id, state
        time.sleep(5.0)


def _role_for_glue(ctx) -> str:
    """A fresh role Glue can assume to run a job, attached with exactly the Glue service policy."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-stop-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    created = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="Glue job execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _undo_role() -> None:
        try:
            for attached in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=name, PolicyArn=attached["PolicyArn"])
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_undo_role)
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return created["Role"]["Arn"]


def _scripts_bucket(ctx) -> str:
    """A bucket holding the two pythonshell scripts the jobs run, under a path Glue's managed
    policy can read (it scopes s3:GetObject to keys containing an "aws-glue-" segment)."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-glue-stop-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    def _put(key: str, body: str) -> None:
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    _put("aws-glue-stop-check/finishes-immediately.py", "print('done')\n")
    _put("aws-glue-stop-check/sleeps-a-while.py", "import time\ntime.sleep(300)\n")
    return bucket


def _create_job(ctx, glue, role: str, bucket: str, script_key: str) -> str:
    name = ctx.unique_name("sim2real-behav-glue-stop-job-")
    glue.create_job(
        Name=name,
        Role=role,
        Command={
            "Name": "pythonshell",
            "PythonVersion": "3.9",
            "ScriptLocation": f"s3://{bucket}/{script_key}",
        },
        MaxCapacity=0.0625,
        Timeout=15,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """batch_stop_job_run refuses an already-SUCCEEDED run with a JobRunCannotBeStoppedException
    entry, keeping it out of SuccessfulSubmissions and its state unchanged, while it accepts a
    just-started run of another job and get_job_run later confirms that run reached STOPPED.
    """
    glue = ctx.client("glue")
    role = _role_for_glue(ctx)
    bucket = _scripts_bucket(ctx)

    finished_job = _create_job(ctx, glue, role, bucket, "aws-glue-stop-check/finishes-immediately.py")
    finished_run_id, finished_state = _run_until_role_is_assumable(glue, finished_job)
    assert finished_state == "SUCCEEDED", (
        f"the trivial script run reached {finished_state!r} instead of SUCCEEDED, "
        "so the stop-of-a-succeeded-run case under test was never set up"
    )

    reject_resp = glue.batch_stop_job_run(JobName=finished_job, JobRunIds=[finished_run_id])
    accepted = {s["JobRunId"] for s in reject_resp.get("SuccessfulSubmissions", [])}
    assert finished_run_id not in accepted, (
        f"batch_stop_job_run put the already-SUCCEEDED run {finished_run_id!r} in "
        f"SuccessfulSubmissions: {reject_resp}"
    )
    errors_by_run = {
        e["JobRunId"]: (e["ErrorDetail"].get("ErrorCode"), e["ErrorDetail"].get("ErrorMessage"))
        for e in reject_resp.get("Errors", [])
    }
    assert errors_by_run.get(finished_run_id) == _STOP_REJECTED, (
        f"expected {_STOP_REJECTED!r} for the already-SUCCEEDED run, "
        f"got {errors_by_run.get(finished_run_id)!r}"
    )
    after_reject_state = glue.get_job_run(JobName=finished_job, RunId=finished_run_id)["JobRun"]["JobRunState"]
    assert after_reject_state == "SUCCEEDED", (
        f"the rejected stop attempt changed the run's state from SUCCEEDED to {after_reject_state!r}"
    )

    running_job = _create_job(ctx, glue, role, bucket, "aws-glue-stop-check/sleeps-a-while.py")
    running_run_id = _start_job_run(glue, running_job)
    accept_resp = glue.batch_stop_job_run(JobName=running_job, JobRunIds=[running_run_id])
    accepted_ids = {s["JobRunId"] for s in accept_resp.get("SuccessfulSubmissions", [])}
    assert running_run_id in accepted_ids, (
        f"batch_stop_job_run did not accept the running job's run {running_run_id!r}: {accept_resp}"
    )
    assert not accept_resp.get("Errors"), (
        f"batch_stop_job_run reported an error for the running job's run: {accept_resp['Errors']}"
    )

    stopped_state = _poll_until(
        lambda: glue.get_job_run(JobName=running_job, RunId=running_run_id)["JobRun"]["JobRunState"],
        lambda s: s in _TERMINAL_STATES,
        timeout_s=240,
    )
    assert stopped_state == "STOPPED", (
        f"an independent get_job_run read reports {stopped_state!r} for the accepted stop "
        "request, not STOPPED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
