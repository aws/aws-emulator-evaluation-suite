"""reject-start-run-of-nonexistent-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-start-run-of-nonexistent-job"
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


def _start_run_awaiting_propagation(glue, name, deadline_s=90.0):
    """StartJobRun probes AssumeRole on the freshly created role; retry the identical
    call, bounded, while that IAM trust grant propagates."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return glue.start_job_run(JobName=name)["JobRunId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartJobRun on an unknown job raises EntityNotFoundException ("Failed to start job run due to
    missing metadata.") and GetJobRuns on it EntityNotFoundException ("Job not found."), while an
    existing job starts a run.
    """
    glue = ctx.client("glue")

    real_job = _create_job(ctx, glue, _glue_role_arn(ctx))
    control_run_id = _start_run_awaiting_propagation(glue, real_job)
    ctx.on_cleanup(lambda: glue.batch_stop_job_run(JobName=real_job, JobRunIds=[control_run_id]))
    assert control_run_id, "positive control: start_job_run on an existing job returned no JobRunId"

    missing_job = ctx.unique_name("sim2real-behav-no-such-job-")
    code, message = _error(lambda: glue.start_job_run(JobName=missing_job))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == "Failed to start job run due to missing metadata.", message

    read_code, read_message = _error(lambda: glue.get_job_runs(JobName=missing_job))
    assert read_code == "EntityNotFoundException", (
        f"expected an independent GetJobRuns read to also report EntityNotFoundException "
        f"for the never-created job, got {read_code}"
    )
    assert read_message == "Job not found.", read_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
