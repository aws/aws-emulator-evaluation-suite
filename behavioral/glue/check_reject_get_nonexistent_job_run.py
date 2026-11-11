"""reject-get-nonexistent-job-run."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-get-nonexistent-job-run"
GROUP = 'overly-permissive'
SERVICES = ['glue']

_ROLE_WAIT_CODES = ("AccessDeniedException", "InvalidInputException")


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
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    """Glue validates the passed role at CreateJob/StartJobRun time, and a freshly
    created role's trust policy is not always visible to that probe yet. Bounded
    retry on the specific propagation errors, never a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _ROLE_WAIT_CODES and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    _retry_role_propagation(lambda: glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real-behavioral-check": CHECK},
    ))
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


def _start_job_run(ctx, glue, job_name):
    """Start a real run so GetJobRun has a genuine RunId to confirm against — the
    positive control that separates 'rejects this RunId' from 'rejects every RunId'."""
    run_id = _retry_role_propagation(lambda: glue.start_job_run(JobName=job_name))["JobRunId"]

    def _stop_quietly():
        try:
            glue.batch_stop_job_run(JobName=job_name, JobRunIds=[run_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_stop_quietly)
    return run_id


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an
    over-permissive target fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected EntityNotFoundException, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """get_job_run for a RunId that was never created must fail with EntityNotFoundException,
    while the RunId of a run that really was started must keep resolving -- otherwise the
    rejection is indistinguishable from a target that fails every GetJobRun call."""
    glue = ctx.client("glue")
    name = _create_job(ctx, glue, _glue_role_arn(ctx))
    real_run_id = _start_job_run(ctx, glue, name)

    # Positive control: the run that really was started is still found.
    found = glue.get_job_run(JobName=name, RunId=real_run_id)["JobRun"]
    assert found["Id"] == real_run_id, f"expected JobRun Id {real_run_id}, got {found.get('Id')}"

    bogus_run_id = real_run_id + "-does-not-exist"
    expected_message = "Job run not found for the given job name and runId."
    code, message = _error_code(lambda: glue.get_job_run(JobName=name, RunId=bogus_run_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
