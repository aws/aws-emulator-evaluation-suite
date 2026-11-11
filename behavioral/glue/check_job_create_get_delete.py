"""job-create-get-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-create-get-delete"
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

def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    """Newly-created IAM roles take time to propagate; CreateJob's AssumeRole probe
    fails with AccessDenied/InvalidInput if we race ahead. Retry on that specific
    class of error only, bounded by a deadline, never an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_job -> get_job reflects the Command/Role -> delete_job removes it."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-job-")
    role = _glue_role_arn(ctx)
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"

    _retry_iam_propagation(lambda: glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))

    resp = glue.get_job(JobName=name)
    job = resp["Job"]
    assert job["Name"] == name, f"expected Name {name!r}, got {job['Name']!r}"
    assert job["Role"] == role, f"expected Role {role!r}, got {job['Role']!r}"
    assert job["Command"]["ScriptLocation"] == script, (
        f"expected ScriptLocation {script!r}, got {job['Command']['ScriptLocation']!r}"
    )

    glue.delete_job(JobName=name)

    expected_message = "Job not found."
    code, message = _error_code(lambda: glue.get_job(JobName=name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == expected_message, f"expected GetJob message {expected_message!r}, got {message!r}"

    expected_message = "Job not found."
    # A complete JobUpdate (Role and Command), so the refusal is about the deleted job and
    # not about a JobUpdate missing its required Command.
    update_code, update_message = _error_code(
        lambda: glue.update_job(
            JobName=name,
            JobUpdate={
                "Role": role,
                "Command": {"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
            },
        )
    )
    assert update_code == "EntityNotFoundException", (
        f"a mutation on a deleted job must also be rejected, got {update_code}"
    )
    assert update_message == expected_message, (
        f"expected UpdateJob message {expected_message!r}, got {update_message!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
