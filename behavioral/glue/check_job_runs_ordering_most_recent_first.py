"""job-runs-ordering-most-recent-first."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-runs-ordering-most-recent-first"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val

def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    """IAM propagation exposes no condition to poll; bound the retry instead of sleeping blind."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """get_job_runs returns JobRuns ordered by most-recently-started first."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    job_name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    # The default MaxConcurrentRuns is 1, which would reject the 2nd/3rd start.
    _retry_call(lambda: glue.create_job(
        Name=job_name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        ExecutionProperty={"MaxConcurrentRuns": 3},
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    run_ids = [glue.start_job_run(JobName=job_name)["JobRunId"] for _ in range(3)]
    assert len(set(run_ids)) == 3, f"each start_job_run must mint a unique RunId: {run_ids}"

    def all_runs_present():
        runs = glue.get_job_runs(JobName=job_name)["JobRuns"]
        return runs if len(runs) >= len(run_ids) else None

    runs = _poll(all_runs_present, lambda r: r is not None, timeout_s=30, interval_s=2)
    assert runs is not None, "the started job runs never all appeared in GetJobRuns"

    started = [r["StartedOn"] for r in runs]
    assert started == sorted(started, reverse=True), (
        f"GetJobRuns is not ordered most-recent-first: {started}"
    )
    returned_ids = {r["Id"] for r in runs}
    assert set(run_ids).issubset(returned_ids), (
        f"expected all started run ids {run_ids} to appear in GetJobRuns, got {returned_ids}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
