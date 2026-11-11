"""trigger-on-demand-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trigger-on-demand-lifecycle"
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
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    # CreateJob validates the Role against IAM, so it raises while a just-created
    # role's trust is still propagating; this bounded retry is the wait.
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

def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val

@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ON_DEMAND trigger fires its job once on start_trigger and remains in CREATED state."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    job_name = _create_job(ctx, glue, role)
    trigger_name = ctx.unique_name("sim2real-behav-trigger-")

    glue.create_trigger(
        Name=trigger_name,
        Type="ON_DEMAND",
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name=trigger_name)

    glue.start_trigger(Name=trigger_name)

    # The job run is dispatched asynchronously; wait for it to appear.
    runs = _poll(
        lambda: glue.get_job_runs(JobName=job_name)["JobRuns"],
        lambda r: bool(r),
        timeout_s=30,
        interval_s=2,
    )
    assert len(runs) == 1, f"ON_DEMAND start_trigger should produce exactly one job run, got {len(runs)}"

    state = glue.get_trigger(Name=trigger_name)["Trigger"]["State"]
    assert state == "CREATED", f"ON_DEMAND trigger should settle back to CREATED, got {state}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
