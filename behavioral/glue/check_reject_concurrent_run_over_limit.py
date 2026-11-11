"""reject-concurrent-run-over-limit."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-concurrent-run-over-limit"
GROUP = 'overly-permissive'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx):
    """Create a dedicated Glue-assumable IAM role for this check and return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
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
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile), deleted on cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


def _start_first_run(glue, name, deadline_s=60.0):
    """Retry start_job_run while Glue's AssumeRole probe of the new role awaits IAM propagation."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return glue.start_job_run(JobName=name)["JobRunId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise AssertionError(f"could not start the first run (code={code})") from exc


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job defaults to MaxConcurrentRuns=1: a second simultaneous StartJobRun raises
    ConcurrentRunsExceededException and leaves no run, and succeeds once the first run finishes."""

    glue = ctx.client("glue")
    name = _create_job(ctx, glue, _glue_role_arn(ctx))

    first = _start_first_run(glue, name)
    assert first

    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}
    state = glue.get_job_run(JobName=name, RunId=first)["JobRun"]["JobRunState"]
    if state in terminal:
        raise AssertionError(f"first run reached {state} before a concurrent run could be attempted")

    code, message = _error(lambda: glue.start_job_run(JobName=name))
    assert code == "ConcurrentRunsExceededException", (
        f"expected ConcurrentRunsExceededException, got {code}"
    )
    assert message == "Concurrent runs exceeded.", message

    run_ids = {r["Id"] for r in glue.get_job_runs(JobName=name)["JobRuns"]}
    assert run_ids == {first}, (
        f"a rejected concurrent start must leave no trace: expected only {first!r} on "
        f"record, got {sorted(run_ids)}"
    )

    poll_deadline = time.monotonic() + 120.0
    while True:
        state = glue.get_job_run(JobName=name, RunId=first)["JobRun"]["JobRunState"]
        if state in terminal:
            break
        if time.monotonic() > poll_deadline:
            raise AssertionError(f"first run never reached a terminal state within 120s (last={state})")
        time.sleep(2)

    # Glue's concurrency counter lags the JobRunState transition: GetJobRun can report
    # a terminal state slightly before StartJobRun stops treating the slot as occupied.
    restore_deadline = time.monotonic() + 60.0
    while True:
        try:
            second = glue.start_job_run(JobName=name)["JobRunId"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ConcurrentRunsExceededException" and time.monotonic() < restore_deadline:
                time.sleep(5)
                continue
            raise AssertionError(
                f"once {first!r} finished ({state}), an identical start_job_run call must "
                f"succeed; got (code={code})"
            ) from exc
    assert second and second != first, (
        f"once {first!r} finished ({state}), the restored call must return a new run id, "
        f"got {second!r}"
    )
    ctx.on_cleanup(lambda: glue.batch_stop_job_run(JobName=name, JobRunIds=[second]))

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
