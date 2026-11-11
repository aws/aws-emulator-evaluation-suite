"""job-update-reflected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-update-reflected"
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
    """Create a pythonshell job (cheapest run profile); track for cleanup.

    A freshly-created IAM role can take a few seconds to propagate before Glue's
    CreateJob role-assumability probe succeeds; retry while that resolves rather than
    sleeping a fixed amount up front.
    """
    from botocore.exceptions import ClientError

    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    kwargs = dict(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            glue.create_job(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_err = e
            time.sleep(3.0)
    else:
        raise AssertionError(f"create_job still rejecting role {role} after 60s: {last_err}")
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """update_job replaces the job definition and the change is visible on get_job."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    name = _create_job(ctx, glue, role)
    new_script = "s3://sim2real-behav-scripts/updated/etl.py"

    glue.update_job(
        JobName=name,
        JobUpdate={
            "Role": role,
            "Command": {
                "Name": "pythonshell",
                "PythonVersion": "3.9",
                "ScriptLocation": new_script,
            },
            "MaxCapacity": 0.0625,
            "Description": "updated-by-behavioral-check",
        },
    )

    job = glue.get_job(JobName=name)["Job"]
    assert job["Command"]["ScriptLocation"] == new_script, (
        f"expected ScriptLocation={new_script!r} after update_job, got {job['Command']!r}"
    )
    assert job.get("Description") == "updated-by-behavioral-check", (
        f"expected Description='updated-by-behavioral-check' after update_job, got {job.get('Description')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
