"""trigger-start-stop-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trigger-start-stop-transitions"
GROUP = 'trigger'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _glue_role_arn(ctx):
    """Create a Glue-assumable IAM role this check owns, with its cleanup registered at once."""
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

    CreateJob validates the Role synchronously against IAM, so it raises while a
    just-created role's AssumeRole trust is still propagating. IAM exposes no
    condition reporting that a role has become assumable by a service, so this
    bounded retry is the wait.
    """
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    deadline = time.monotonic() + 120
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
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidInputException",
                                                       "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

def _stop_trigger_quiet(glue, name):
    """Teardown: StopTrigger refuses a trigger that is not started, which is fine here."""
    try:
        glue.stop_trigger(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "InvalidInputException",
            "EntityNotFoundException",
        ):
            raise


def _track_trigger(ctx, glue, name):
    # LIFO: the stop runs before delete_trigger.
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=name))
    ctx.on_cleanup(lambda: _stop_trigger_quiet(glue, name))

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SCHEDULED trigger goes CREATED -> ACTIVATED on start_trigger and -> DEACTIVATED on stop_trigger."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-trigger-")
    job_name = _create_job(ctx, glue, _glue_role_arn(ctx))

    glue.create_trigger(
        Name=name,
        Type="SCHEDULED",
        Schedule="cron(0 12 * * ? *)",
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name)

    state = glue.get_trigger(Name=name)["Trigger"]["State"]
    assert state == "CREATED", state

    glue.start_trigger(Name=name)
    state = None
    _deadline = time.monotonic() + 120
    while time.monotonic() < _deadline:
        state = glue.get_trigger(Name=name)["Trigger"]["State"]
        if state == "ACTIVATED":
            break
        time.sleep(2)
    assert state == "ACTIVATED", state

    glue.stop_trigger(Name=name)
    state = None
    _deadline = time.monotonic() + 120
    while time.monotonic() < _deadline:
        state = glue.get_trigger(Name=name)["Trigger"]["State"]
        if state == "DEACTIVATED":
            break
        time.sleep(2)
    assert state == "DEACTIVATED", state

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
