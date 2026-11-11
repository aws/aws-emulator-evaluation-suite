"""job-start-run-reaches-terminal-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-start-run-reaches-terminal-state"
GROUP = 'job'
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
    """Create a dedicated, self-cleaning Glue-assumable IAM role and return its ARN."""
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
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

def _start_job_run_with_retry(glue, name):
    """Glue's AssumeRole probe against the check's just-created role can reject for a window after
    IAM's create_role/attach_role_policy calls return; retry until it succeeds or the deadline passes."""
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=name)
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """start_job_run produces a JobRunId whose state progresses to a terminal state (SUCCEEDED/FAILED/STOPPED/ERROR)."""
    glue = ctx.client("glue")
    name = _create_job(ctx, glue, _glue_role_arn(ctx))

    run = _start_job_run_with_retry(glue, name)
    run_id = run["JobRunId"]
    assert run_id, "start_job_run returned no JobRunId"

    terminal_states = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}

    # A fresh run must start in a non-terminal state: the run is asynchronous.
    first_state = glue.get_job_run(JobName=name, RunId=run_id)["JobRun"]["JobRunState"]
    assert first_state not in terminal_states, (
        f"job run reported terminal state {first_state} immediately after start_job_run"
    )

    final_state = None
    _deadline = time.monotonic() + 900
    while time.monotonic() < _deadline:
        final_state = glue.get_job_run(JobName=name, RunId=run_id)["JobRun"]["JobRunState"]
        if final_state in terminal_states:
            break
        time.sleep(2)
    assert final_state in terminal_states, final_state

    # The run must also show up in get_job_runs for the job.
    runs = glue.get_job_runs(JobName=name)
    run_ids = {r["Id"] for r in runs["JobRuns"]}
    assert run_id in run_ids, f"expected {run_id} in {run_ids}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
