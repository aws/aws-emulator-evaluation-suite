"""job-run-arguments-propagated."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-run-arguments-propagated"
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
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


def _start_job_run(glue, *, timeout_s: float = 90.0, **kwargs) -> str:
    """StartJobRun validates synchronously that Glue can assume the job's role, so it raises
    while IAM propagation for a just-created role is still in flight. IAM exposes no condition
    reporting that a role has become assumable by a service, so this bounded retry is the wait."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return glue.start_job_run(**kwargs)["JobRunId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidInputException", "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Arguments passed to start_job_run are echoed back verbatim on get_job_run."""
    glue = ctx.client("glue")
    name = _create_job(ctx, glue, _glue_role_arn(ctx))

    run_id = _start_job_run(glue, JobName=name, Arguments={"--my-custom-arg": "hello-world"})

    resp = glue.get_job_run(JobName=name, RunId=run_id)
    args = resp["JobRun"].get("Arguments", {})
    assert args.get("--my-custom-arg") == "hello-world", (
        f"expected Arguments['--my-custom-arg']=='hello-world' on the independent GetJobRun "
        f"read, got {args!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
