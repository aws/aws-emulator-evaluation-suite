"""reject-update-trigger-without-actions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-update-trigger-without-actions"
GROUP = 'overly-permissive'
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
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile), retrying while Glue's PassRole probe
    rejects the just-created role during IAM propagation."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    deadline = time.monotonic() + 60.0
    while True:
        try:
            glue.create_job(
                Name=name,
                Role=role,
                Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
                MaxCapacity=0.0625,
                Timeout=10,
                Tags={"sim2real-behavioral": CHECK},
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline or code not in (
                "InvalidInputException",
                "AccessDeniedException",
            ):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

def _stop_trigger_if_started(glue, name):
    """Teardown: a SCHEDULED trigger created without StartOnCreation stays CREATED, and
    StopTrigger refuses a trigger that was never started."""
    try:
        glue.stop_trigger(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInputException":
            raise


def _track_trigger(ctx, glue, name):
    # LIFO: stop_trigger runs before delete_trigger.
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=name))
    ctx.on_cleanup(lambda: _stop_trigger_if_started(glue, name))


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
    """UpdateTrigger with a TriggerUpdate lacking Actions raises InvalidInputException and changes
    nothing, because TriggerUpdate is a whole-object replacement; a full TriggerUpdate succeeds."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-trigger-")
    action_job = _create_job(ctx, glue, _glue_role_arn(ctx))

    glue.create_trigger(
        Name=name,
        Type="SCHEDULED",
        Schedule="cron(0 12 * * ? *)",
        Actions=[{"JobName": action_job}],
        Tags={"sim2real-behavioral": CHECK},
    )
    _track_trigger(ctx, glue, name)

    # Positive control: a full, valid TriggerUpdate (Schedule + Actions present)
    # must succeed and take effect, read back independently.
    glue.update_trigger(
        Name=name,
        TriggerUpdate={"Schedule": "cron(0 6 * * ? *)", "Actions": [{"JobName": action_job}]},
    )
    trig = glue.get_trigger(Name=name)["Trigger"]
    assert trig["Schedule"] == "cron(0 6 * * ? *)", (
        f"positive control: expected schedule cron(0 6 * * ? *) after a valid "
        f"UpdateTrigger, got {trig['Schedule']!r}"
    )

    code, message = _error(
        lambda: glue.update_trigger(
            Name=name,
            TriggerUpdate={"Schedule": "cron(0 18 * * ? *)"},
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == "Actions cannot be null or empty", message

    # The definition set by the positive control must be intact: the invalid
    # update must not have taken effect.
    trig = glue.get_trigger(Name=name)["Trigger"]
    assert trig["Actions"][0]["JobName"] == action_job, (
        f"expected action job {action_job!r} unchanged, got {trig['Actions']}"
    )
    assert trig["Schedule"] == "cron(0 6 * * ? *)", (
        f"expected schedule unchanged at cron(0 6 * * ? *) after rejected update, "
        f"got {trig['Schedule']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
