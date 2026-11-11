"""create-trigger-invalid-cron-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trigger-invalid-cron-fails"
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
    """Create a self-cleaning Glue-assumable IAM role and return its ARN."""
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

def _create_job(ctx, glue, role, *, timeout_s: float = 60.0):
    """Create a pythonshell job (cheapest run profile); track for cleanup.

    CreateJob validates synchronously that Glue can assume the role, so it raises while IAM
    propagation on a freshly created role is still in flight. IAM exposes no condition
    reporting that a role has become assumable by a service, so this bounded retry is the
    wait -- never an unconditional sleep.
    """
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_job(
                Name=name,
                Role=role,
                Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
                MaxCapacity=0.0625,
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidInputException", "AccessDeniedException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrigger Type=SCHEDULED with a non-cron Schedule raises InvalidInputException with the
    exact message and GetTrigger then raises EntityNotFoundException ("Trigger not found."); a
    valid cron trigger is created as given.
    """
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    job_name = _create_job(ctx, glue, role)

    control_name = ctx.unique_name("sim2real-behav-trigger-ctrl-")
    glue.create_trigger(
        Name=control_name,
        Type="SCHEDULED",
        Schedule="cron(0 12 * * ? *)",
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=control_name))
    control = glue.get_trigger(Name=control_name)["Trigger"]
    assert control.get("Schedule") == "cron(0 12 * * ? *)", (
        f"positive control: expected the valid cron schedule to be accepted and stored, "
        f"got {control.get('Schedule')!r}"
    )

    trigger_name = ctx.unique_name("sim2real-behav-trigger-")
    try:
        glue.create_trigger(
            Name=trigger_name,
            Type="SCHEDULED",
            Schedule="every-so-often",
            Actions=[{"JobName": job_name}],
            Tags={"sim2real": CHECK},
        )
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    if code is None:
        ctx.on_cleanup(lambda: glue.delete_trigger(Name=trigger_name))
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for a malformed cron Schedule, got {code}"
    )
    expected = "The schedule every-so-often is invalid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found, not_found_message = None, None
    try:
        glue.get_trigger(Name=trigger_name)
    except ClientError as exc:
        not_found = exc.response.get("Error", {}).get("Code")
        not_found_message = exc.response.get("Error", {}).get("Message")
    assert not_found == "EntityNotFoundException", (
        f"a rejected create_trigger must leave no trigger behind, expected "
        f"EntityNotFoundException from an independent get_trigger, got {not_found}"
    )
    assert not_found_message == "Trigger not found.", (
        f"unexpected not-found message {not_found_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
