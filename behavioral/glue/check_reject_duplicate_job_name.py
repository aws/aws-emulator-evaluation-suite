"""reject-duplicate-job-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-duplicate-job-name"
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

def _create_job_awaiting_propagation(glue, *, name, role, command, max_capacity, timeout, deadline_s=90, poll_s=5):
    """CreateJob can race the IAM role's AssumeRole propagation like CreateCrawler's probe
    does, so retry on the specific role-not-ready error up to a deadline instead of a fixed
    sleep -- a slow-but-correct target must not be penalized."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            glue.create_job(
                Name=name,
                Role=role,
                Command=command,
                MaxCapacity=max_capacity,
                Timeout=timeout,
                Tags={"sim2real": CHECK},
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidInputException", "AccessDeniedException") or time.monotonic() >= deadline:
                raise
            time.sleep(poll_s)

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    _create_job_awaiting_propagation(
        glue,
        name=name,
        role=role,
        command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        max_capacity=0.0625,
        timeout=10,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


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
    """CreateJob is idempotent on the name: an identical repeat succeeds unchanged, while a
    differing definition raises IdempotentParameterMismatchException with the exact message and
    leaves the ScriptLocation unchanged.
    """
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    name = _create_job(ctx, glue, role)
    original_script = glue.get_job(JobName=name)["Job"]["Command"]["ScriptLocation"]
    identical_command = {
        "Name": "pythonshell",
        "PythonVersion": "3.9",
        "ScriptLocation": original_script,
    }

    # Positive control: a repeat CreateJob with the IDENTICAL definition is accepted
    # (idempotent), not rejected -- otherwise a target that rejects every second
    # CreateJob for an existing name would pass the mismatch leg below for free.
    glue.create_job(Name=name, Role=role, Command=identical_command, MaxCapacity=0.0625, Timeout=10)
    same = glue.get_job(JobName=name)["Job"]["Command"]["ScriptLocation"]
    assert same == original_script, f"identical CreateJob replay changed the job: {same}"

    # Break exactly one thing: the same name, a differing definition.
    code, message = _error(
        lambda: glue.create_job(
            Name=name,
            Role=role,
            Command={
                "Name": "pythonshell",
                "PythonVersion": "3.9",
                "ScriptLocation": "s3://sim2real-behav-other/other.py",
            },
            MaxCapacity=0.0625,
            Timeout=10,
        )
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException, got {code}"
    )
    assert message == "Job already submitted with different configuration.", message

    # The original definition must be untouched.
    after = glue.get_job(JobName=name)["Job"]["Command"]["ScriptLocation"]
    assert after == original_script, f"job was overwritten: {after}"

    # Restore: the identical call succeeds again, proving the failed mismatch attempt
    # left no corrupted state behind.
    glue.create_job(Name=name, Role=role, Command=identical_command, MaxCapacity=0.0625, Timeout=10)
    restored = glue.get_job(JobName=name)["Job"]["Command"]["ScriptLocation"]
    assert restored == original_script, f"job changed after restore call: {restored}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
